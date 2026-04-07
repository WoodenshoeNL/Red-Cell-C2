//! `red_cell` / `havoc` plugin surface: commands, loot, tasks, options, and validation errors.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::IntoPyDict;
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tempfile::TempDir;

use super::super::*;
use super::helpers::*;

#[test]
fn runtime_executes_registered_commands() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("command.txt");
    let script = format!(
        "import pathlib\nimport red_cell\n\
def demo(agent, args):\n    pathlib.Path({output:?}).write_text(agent.id + ':' + ','.join(args))\n    return 'handled ' + agent.info['hostname']\n\
red_cell.register_command('demo', demo)\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("demo.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let executed = runtime
        .execute_registered_command("00ABCDEF", "demo alpha bravo")
        .unwrap_or_else(|error| panic!("registered command should run: {error}"));

    assert!(executed);
    assert_eq!(wait_for_file_contents(&output_path).as_deref(), Some("00ABCDEF:alpha,bravo"));
    assert!(wait_for_output(&runtime, "handled wkstn-01"));
}
#[test]
fn runtime_accepts_havoc_style_command_registration_and_context_callbacks() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("context.txt");
    let script = format!(
        "import pathlib\nimport havoc\n\
def run(context):\n    pathlib.Path({output:?}).write_text(context.command_line + '|' + context.agent.id)\n    return context.description or ''\n\
havoc.RegisterCommand(function=run, module='situational_awareness', command='whoami', description='demo command')\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("compat.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert_eq!(runtime.command_names(), vec!["situational_awareness whoami".to_owned()]);

    let executed = runtime
        .execute_registered_command("00ABCDEF", "situational_awareness whoami /all")
        .unwrap_or_else(|error| panic!("havoc-style command should run: {error}"));

    assert!(executed);
    assert_eq!(
        wait_for_file_contents(&output_path).as_deref(),
        Some("situational_awareness whoami /all|00ABCDEF")
    );
    assert!(wait_for_output(&runtime, "demo command"));
}
#[test]
fn runtime_preserves_original_argument_casing_for_registered_commands() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("preserved_case.txt");
    let script = format!(
        "import json\nimport pathlib\nimport red_cell\n\
def demo(context):\n    payload = {{'command_line': context.command_line, 'args': context.args}}\n    pathlib.Path({output:?}).write_text(json.dumps(payload))\n\
red_cell.register_command('demo', demo)\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("preserve.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let executed = runtime
        .execute_registered_command("00ABCDEF", "DeMo C:\\Temp\\Foo.txt MiXeDCaseToken")
        .unwrap_or_else(|error| panic!("registered command should run: {error}"));

    assert!(executed);
    assert_eq!(
        wait_for_file_contents(&output_path).as_deref(),
        Some(
            "{\"command_line\": \"DeMo C:\\\\Temp\\\\Foo.txt MiXeDCaseToken\", \
\"args\": [\"C:\\\\Temp\\\\Foo.txt\", \"MiXeDCaseToken\"]}"
        )
    );
}
#[test]
fn demon_command_queues_agent_task_messages() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let script = "import havoc\n\
def queue(agent, args):\n    demon = havoc.Demon(agent.id)\n    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, 'queued pwd')\n    demon.Command(task_id, 'pwd')\n\
havoc.RegisterCommand(function=queue, module='ops', command='pwd', description='queue pwd')\n";
    write_script(&temp_dir.path().join("queue_task.py"), script);
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
        state.operator_info = Some(red_cell_common::OperatorInfo {
            username: "operator".to_owned(),
            password_hash: None,
            role: None,
            online: true,
            last_seen: None,
        });
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));
    let (outgoing_tx, mut outgoing_rx) = tokio::sync::mpsc::unbounded_channel();
    runtime.set_outgoing_sender(outgoing_tx);

    let executed = runtime
        .execute_registered_command("00ABCDEF", "ops pwd")
        .unwrap_or_else(|error| panic!("registered command should run: {error}"));
    assert!(executed);

    let Some(OperatorMessage::AgentTask(message)) = outgoing_rx.blocking_recv() else {
        panic!("expected queued agent task");
    };
    assert_eq!(message.head.user, "operator");
    assert_eq!(message.info.demon_id, "00ABCDEF");
    assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandFs).to_string());
    assert_eq!(message.info.sub_command.as_deref(), Some("pwd"));
}
#[test]
fn agent_proxy_returns_live_agent_info() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(&temp_dir.path().join("noop.py"), "import red_cell\n");
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
    }
    let _runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let result = Python::with_gil(|py| -> PyResult<String> {
        install_api_module(py)?;
        let module = py.import("red_cell")?;
        let agent = module.call_method1("agent", ("00ABCDEF",))?;
        agent.getattr("info")?.get_item("hostname")?.extract::<String>()
    })
    .unwrap_or_else(|error| panic!("python agent lookup should succeed: {error}"));

    assert_eq!(result, "wkstn-01");
}
#[test]
fn havoc_alias_exposes_agent_and_listener_accessors() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(&temp_dir.path().join("noop.py"), "import red_cell\n");
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
        Arc::make_mut(&mut state.listeners).push(sample_listener("https"));
    }
    let _runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let result = Python::with_gil(|py| -> PyResult<(String, usize, String, usize)> {
        install_api_module(py)?;
        let module = py.import("havoc")?;
        let agent_name = module
            .call_method0("agents")?
            .get_item(0)?
            .getattr("info")?
            .get_item("hostname")?
            .extract::<String>()?;
        let agent_count = module.call_method0("agents")?.len()?;
        let listener_status = module
            .call_method1("listener", ("https",))?
            .getattr("info")?
            .get_item("status")?
            .extract::<String>()?;
        let listener_count = module.call_method0("listeners")?.len()?;
        Ok((agent_name, agent_count, listener_status, listener_count))
    })
    .unwrap_or_else(|error| panic!("havoc alias lookup should succeed: {error}"));

    assert_eq!(result, ("wkstn-01".to_owned(), 1, "Online".to_owned(), 1));
}
#[test]
fn get_loot_returns_all_items_when_no_filter() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(&temp_dir.path().join("noop.py"), "import red_cell\n");
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.loot).push(sample_loot_item(
            "00AABBCC",
            crate::transport::LootKind::Credential,
            "cred-1",
            Some("dXNlcjpwYXNz"),
        ));
        Arc::make_mut(&mut state.loot).push(sample_loot_item(
            "00DDEEFF",
            crate::transport::LootKind::File,
            "file-1",
            Some("ZmlsZWNvbnRlbnQ="),
        ));
    }
    let _runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let (count, first_agent_id, first_type, first_id, first_timestamp) =
        Python::with_gil(|py| -> PyResult<(usize, String, String, Option<i64>, String)> {
            install_api_module(py)?;
            let module = py.import("red_cell")?;
            let items = module.call_method0("get_loot")?;
            let count = items.len()?;
            let first = items.get_item(0)?;
            let agent_id = first.getattr("agent_id")?.extract::<String>()?;
            let loot_type = first.getattr("type")?.extract::<String>()?;
            let id = first.getattr("id")?.extract::<Option<i64>>()?;
            let timestamp = first.getattr("timestamp")?.extract::<String>()?;
            Ok((count, agent_id, loot_type, id, timestamp))
        })
        .unwrap_or_else(|error| panic!("get_loot should succeed: {error}"));

    assert_eq!(count, 2);
    assert_eq!(first_agent_id, "00AABBCC");
    assert_eq!(first_type, "Credential");
    assert_eq!(first_id, Some(42));
    assert_eq!(first_timestamp, "2026-03-15T12:00:00Z");
}
#[test]
fn get_loot_filters_by_agent_id_and_type() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(&temp_dir.path().join("noop.py"), "import red_cell\n");
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.loot).push(sample_loot_item(
            "00AABBCC",
            crate::transport::LootKind::Credential,
            "cred-1",
            Some("dXNlcjpwYXNz"),
        ));
        Arc::make_mut(&mut state.loot).push(sample_loot_item(
            "00AABBCC",
            crate::transport::LootKind::File,
            "file-1",
            Some("ZmlsZWNvbnRlbnQ="),
        ));
        Arc::make_mut(&mut state.loot).push(sample_loot_item(
            "00DDEEFF",
            crate::transport::LootKind::Credential,
            "cred-2",
            None,
        ));
    }
    let _runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    // Filter by agent_id only.
    let agent_filtered_count = Python::with_gil(|py| -> PyResult<usize> {
        install_api_module(py)?;
        let module = py.import("red_cell")?;
        module
            .call_method("get_loot", (), Some(&[("agent_id", "00AABBCC")].into_py_dict(py)?))?
            .len()
    })
    .unwrap_or_else(|error| panic!("get_loot with agent_id filter should succeed: {error}"));
    assert_eq!(agent_filtered_count, 2);

    // Filter by loot_type only.
    let type_filtered_count = Python::with_gil(|py| -> PyResult<usize> {
        install_api_module(py)?;
        let module = py.import("red_cell")?;
        module
            .call_method("get_loot", (), Some(&[("loot_type", "credential")].into_py_dict(py)?))?
            .len()
    })
    .unwrap_or_else(|error| panic!("get_loot with type filter should succeed: {error}"));
    assert_eq!(type_filtered_count, 2);

    // Filter by both agent_id and loot_type.
    let both_filtered = Python::with_gil(|py| -> PyResult<(usize, Option<String>)> {
        install_api_module(py)?;
        let module = py.import("red_cell")?;
        let items = module.call_method(
            "get_loot",
            (),
            Some(&[("agent_id", "00AABBCC"), ("loot_type", "Credential")].into_py_dict(py)?),
        )?;
        let count = items.len()?;
        let data = items.get_item(0)?.getattr("data")?.extract::<Option<String>>()?;
        Ok((count, data))
    })
    .unwrap_or_else(|error| panic!("get_loot with both filters should succeed: {error}"));
    assert_eq!(both_filtered.0, 1);
    assert_eq!(both_filtered.1.as_deref(), Some("dXNlcjpwYXNz"));
}
#[test]
fn task_agent_returns_task_id_and_queues_message() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_mutex(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("AABBCCDD"));
    }

    let runtime = PythonRuntime::initialize(app_state.clone(), temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    // Attach a channel so queue_task_message succeeds.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OperatorMessage>();
    runtime.set_outgoing_sender(tx);

    let task_id = Python::with_gil(|py| -> PyResult<String> {
        install_api_module(py)?;
        let module = py.import("red_cell")?;
        module.call_method("task_agent", ("AABBCCDD", "ps"), None)?.extract::<String>()
    })
    .unwrap_or_else(|error| panic!("task_agent should succeed: {error}"));

    assert_eq!(task_id.len(), 8, "task_id should be an 8-character hex string");
    rx.try_recv().unwrap_or_else(|error| panic!("a message should have been queued: {error}"));
}
#[test]
fn get_task_result_fails_without_prior_task_agent() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    let _runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let result = Python::with_gil(|py| -> PyResult<()> {
        install_api_module(py)?;
        let module = py.import("red_cell")?;
        module.call_method("get_task_result", ("DEADBEEF",), None)?;
        Ok(())
    });

    assert!(result.is_err(), "get_task_result with unknown task_id should fail");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("DEADBEEF"), "error should mention the task id");
}
#[test]
fn notify_task_result_unblocks_get_task_result() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_mutex(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("11223344"));
    }

    let runtime = PythonRuntime::initialize(app_state.clone(), temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<OperatorMessage>();
    runtime.set_outgoing_sender(tx);

    // Allocate a task and get the task_id.
    let task_id = Python::with_gil(|py| -> PyResult<String> {
        install_api_module(py)?;
        let module = py.import("red_cell")?;
        module.call_method("task_agent", ("11223344", "screenshot"), None)?.extract::<String>()
    })
    .unwrap_or_else(|error| panic!("task_agent should succeed: {error}"));

    // Deliver the result from a separate thread before get_task_result is called.
    let runtime_clone = runtime.clone();
    let task_id_clone = task_id.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        runtime_clone.notify_task_result(
            task_id_clone,
            "11223344".to_owned(),
            "screenshot saved".to_owned(),
        );
    });

    let result = Python::with_gil(|py| -> PyResult<(String, String)> {
        install_api_module(py)?;
        let module = py.import("red_cell")?;
        let res = module.call_method("get_task_result", (&task_id,), None)?;
        let agent_id = res.get_item("agent_id")?.extract::<String>()?;
        let output = res.get_item("output")?.extract::<String>()?;
        Ok((agent_id, output))
    })
    .unwrap_or_else(|error| panic!("get_task_result should succeed: {error}"));

    assert_eq!(result.0, "11223344");
    assert_eq!(result.1, "screenshot saved");
}
#[test]
fn get_task_result_times_out_and_returns_none() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_mutex(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("DEADBEEF"));
    }

    let runtime = PythonRuntime::initialize(app_state.clone(), temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<OperatorMessage>();
    runtime.set_outgoing_sender(tx);

    let task_id = Python::with_gil(|py| -> PyResult<String> {
        install_api_module(py)?;
        let module = py.import("red_cell")?;
        module.call_method("task_agent", ("DEADBEEF", "screenshot"), None)?.extract::<String>()
    })
    .unwrap_or_else(|error| panic!("task_agent should succeed: {error}"));

    // get_task_result with a tiny timeout; nobody will deliver the result.
    let is_none = Python::with_gil(|py| -> PyResult<bool> {
        install_api_module(py)?;
        let module = py.import("red_cell")?;
        let res = module.call_method(
            "get_task_result",
            (&task_id,),
            Some(&[("timeout", 0.01f64)].into_py_dict(py)?),
        )?;
        Ok(res.is_none())
    })
    .unwrap_or_else(|error| panic!("get_task_result should not error: {error}"));

    assert!(is_none, "get_task_result should return None on timeout");

    // After timeout the sender must be removed from the map so it does not leak.
    let api_state = Python::with_gil(|py| -> PyResult<Arc<PythonApiState>> {
        install_api_module(py)?;
        active_api_state()
    })
    .unwrap_or_else(|error| panic!("active_api_state should be available: {error}"));
    assert!(
        !lock_mutex(&api_state.task_result_senders).contains_key(&task_id),
        "sender for timed-out task should have been removed from task_result_senders",
    );
}
#[test]
fn register_command_accepts_options_and_exposes_them_via_context() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("opts.txt");
    let script = format!(
        "import json\nimport pathlib\nimport red_cell\n\
def cmd(context):\n    opts = [dict(name=o.name, type=o.type, required=o.required, default=o.default) for o in context.options]\n    pathlib.Path({output:?}).write_text(json.dumps(opts))\n\
options = [\n    {{'name': 'target', 'type': 'string', 'required': True}},\n    {{'name': 'timeout', 'type': 'int', 'required': False, 'default': '30'}},\n    {{'name': 'verbose', 'type': 'bool', 'required': False}},\n    {{'name': 'output', 'type': 'file', 'required': False}},\n]\n\
red_cell.register_command('demo', cmd, options=options)\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("opts.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let executed = runtime
        .execute_registered_command("00ABCDEF", "demo localhost")
        .unwrap_or_else(|error| panic!("registered command should run: {error}"));

    assert!(executed);
    let contents = wait_for_file_contents(&output_path)
        .unwrap_or_else(|| panic!("output file should be written"));
    let opts: Vec<serde_json::Value> =
        serde_json::from_str(&contents).expect("output should be valid JSON");
    assert_eq!(opts.len(), 4);
    assert_eq!(opts[0]["name"], "target");
    assert_eq!(opts[0]["type"], "string");
    assert_eq!(opts[0]["required"], true);
    assert_eq!(opts[0]["default"], serde_json::Value::Null);
    assert_eq!(opts[1]["name"], "timeout");
    assert_eq!(opts[1]["type"], "int");
    assert_eq!(opts[1]["required"], false);
    assert_eq!(opts[1]["default"], "30");
    assert_eq!(opts[2]["type"], "bool");
    assert_eq!(opts[3]["type"], "file");
}
#[test]
fn command_history_is_empty_on_first_invocation_and_grows_on_subsequent() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("history.txt");
    let script = format!(
        "import json\nimport pathlib\nimport red_cell\n\
def cmd(context):\n    pathlib.Path({output:?}).write_text(json.dumps(context.history))\n\
red_cell.register_command('hist', cmd)\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("hist.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    // First invocation — history must be empty.
    runtime
        .execute_registered_command("00ABCDEF", "hist alpha")
        .unwrap_or_else(|e| panic!("should run: {e}"));
    let first =
        wait_for_file_contents(&output_path).unwrap_or_else(|| panic!("output should be written"));
    let hist: Vec<String> = serde_json::from_str(&first).expect("valid JSON");
    assert!(hist.is_empty(), "history should be empty on first invocation");

    // Second invocation — history must contain the first command.
    std::fs::remove_file(&output_path).ok();
    runtime
        .execute_registered_command("00ABCDEF", "hist beta")
        .unwrap_or_else(|e| panic!("should run: {e}"));
    let second =
        wait_for_file_contents(&output_path).unwrap_or_else(|| panic!("output should be written"));
    let hist: Vec<String> = serde_json::from_str(&second).expect("valid JSON");
    assert_eq!(hist, vec!["hist alpha".to_owned()]);

    // Third invocation — history contains both prior commands in order.
    std::fs::remove_file(&output_path).ok();
    runtime
        .execute_registered_command("00ABCDEF", "hist gamma")
        .unwrap_or_else(|e| panic!("should run: {e}"));
    let third =
        wait_for_file_contents(&output_path).unwrap_or_else(|| panic!("output should be written"));
    let hist: Vec<String> = serde_json::from_str(&third).expect("valid JSON");
    assert_eq!(hist, vec!["hist alpha".to_owned(), "hist beta".to_owned()]);
}
#[test]
fn command_history_is_scoped_per_agent() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("scoped_hist.txt");
    let script = format!(
        "import json\nimport pathlib\nimport red_cell\n\
def cmd(context):\n    pathlib.Path({output:?}).write_text(json.dumps(context.history))\n\
red_cell.register_command('scoped', cmd)\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("scoped.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("AABBCCDD"));
        Arc::make_mut(&mut state.agents).push(sample_agent("11223344"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    // Invoke on agent A.
    runtime
        .execute_registered_command("AABBCCDD", "scoped from_a")
        .unwrap_or_else(|e| panic!("should run: {e}"));
    let _ = wait_for_file_contents(&output_path);

    // Invoke on agent B — history must be empty (different agent).
    std::fs::remove_file(&output_path).ok();
    runtime
        .execute_registered_command("11223344", "scoped from_b")
        .unwrap_or_else(|e| panic!("should run: {e}"));
    let contents =
        wait_for_file_contents(&output_path).unwrap_or_else(|| panic!("output should be written"));
    let hist: Vec<String> = serde_json::from_str(&contents).expect("valid JSON");
    assert!(hist.is_empty(), "agent B should start with empty history");
}
#[test]
fn havocui_register_command_two_arg_form_is_backward_compatible() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("ui_cmd.txt");
    let script = format!(
        "import pathlib\nimport havocui\n\
def run(context):\n    pathlib.Path({output:?}).write_text('ok:' + context.command_line)\n\
havocui.RegisterCommand('ui cmd', run)\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("ui_cmd.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let executed = runtime
        .execute_registered_command("00ABCDEF", "ui cmd")
        .unwrap_or_else(|e| panic!("should run: {e}"));
    assert!(executed);
    assert_eq!(wait_for_file_contents(&output_path).as_deref(), Some("ok:ui cmd"));
}
#[test]
fn havocui_register_command_four_arg_form_exposes_description_and_options() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("ui_full.txt");
    let script = format!(
        "import json\nimport pathlib\nimport havocui\n\
def run(context):\n    payload = {{'description': context.description, 'options': [o.name for o in context.options]}}\n    pathlib.Path({output:?}).write_text(json.dumps(payload))\n\
havocui.RegisterCommand('recon scan', 'Run a recon scan', [{{'name': 'target', 'type': 'string', 'required': True}}], run)\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("ui_full.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let executed = runtime
        .execute_registered_command("00ABCDEF", "recon scan 10.0.0.1")
        .unwrap_or_else(|e| panic!("should run: {e}"));
    assert!(executed);
    let contents =
        wait_for_file_contents(&output_path).unwrap_or_else(|| panic!("output should be written"));
    let payload: serde_json::Value = serde_json::from_str(&contents).expect("valid JSON");
    assert_eq!(payload["description"], "Run a recon scan");
    assert_eq!(payload["options"], serde_json::json!(["target"]));
}
#[test]
fn task_agent_cleans_up_waiter_when_no_sender_configured() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_mutex(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("AABB0001"));
    }

    let _runtime = PythonRuntime::initialize(app_state.clone(), temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    // Do NOT attach an outgoing sender — queue_task_message should fail.
    let result = Python::with_gil(|py| -> PyResult<String> {
        install_api_module(py)?;
        let module = py.import("red_cell")?;
        module.call_method("task_agent", ("AABB0001", "ps"), None)?.extract::<String>()
    });

    assert!(result.is_err(), "task_agent should fail when no sender is configured");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not connected"),
        "error should mention transport not connected, got: {err_msg}"
    );

    // Verify no stale waiter state was left behind.
    let api_state = Python::with_gil(|py| -> PyResult<Arc<PythonApiState>> {
        install_api_module(py)?;
        active_api_state()
    })
    .unwrap_or_else(|error| panic!("active_api_state should be available: {error}"));
    assert!(
        lock_mutex(&api_state.task_result_senders).is_empty(),
        "task_result_senders should be empty after enqueue failure"
    );
    assert!(
        lock_mutex(&api_state.task_result_receivers).is_empty(),
        "task_result_receivers should be empty after enqueue failure"
    );
}
#[test]
fn task_agent_cleans_up_waiter_when_sender_is_closed() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_mutex(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("AABB0002"));
    }

    let runtime = PythonRuntime::initialize(app_state.clone(), temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    // Attach a sender then immediately close it by dropping the receiver.
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<OperatorMessage>();
    runtime.set_outgoing_sender(tx);
    drop(rx);

    let result = Python::with_gil(|py| -> PyResult<String> {
        install_api_module(py)?;
        let module = py.import("red_cell")?;
        module.call_method("task_agent", ("AABB0002", "ps"), None)?.extract::<String>()
    });

    assert!(result.is_err(), "task_agent should fail when the sender channel is closed");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("closed"),
        "error should mention the queue being closed, got: {err_msg}"
    );

    // Verify no stale waiter state was left behind.
    let api_state = Python::with_gil(|py| -> PyResult<Arc<PythonApiState>> {
        install_api_module(py)?;
        active_api_state()
    })
    .unwrap_or_else(|error| panic!("active_api_state should be available: {error}"));
    assert!(
        lock_mutex(&api_state.task_result_senders).is_empty(),
        "task_result_senders should be empty after closed-sender enqueue failure"
    );
    assert!(
        lock_mutex(&api_state.task_result_receivers).is_empty(),
        "task_result_receivers should be empty after closed-sender enqueue failure"
    );
}
#[test]
fn register_command_rejects_non_callable_callback() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("bad_cb.py"),
        "import red_cell\nred_cell.register_command('oops', 'not_a_function')\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert!(
        runtime.command_names().is_empty(),
        "no command should be registered when the callback is not callable"
    );
    let descriptor = runtime
        .script_descriptors()
        .into_iter()
        .find(|s| s.name == "bad_cb")
        .expect("script descriptor should exist");
    assert_eq!(descriptor.status, ScriptLoadStatus::Error);
    assert!(
        descriptor.error.as_ref().is_some_and(|e| e.contains("callback must be callable")),
        "error should mention non-callable callback, got: {:?}",
        descriptor.error,
    );
}
#[test]
fn havocui_register_command_rejects_non_callable_callback() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("bad_ui_cb.py"),
        "import havocui\nhavocui.RegisterCommand('oops', 42)\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert!(
        runtime.command_names().is_empty(),
        "no command should be registered when havocui callback is not callable"
    );
    let descriptor = runtime
        .script_descriptors()
        .into_iter()
        .find(|s| s.name == "bad_ui_cb")
        .expect("script descriptor should exist");
    assert_eq!(descriptor.status, ScriptLoadStatus::Error);
    assert!(
        descriptor
            .error
            .as_ref()
            .is_some_and(|e| { e.contains("callable") || e.contains("callback") }),
        "error should mention callable requirement, got: {:?}",
        descriptor.error,
    );
}
#[test]
fn register_callback_rejects_non_callable() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("bad_event.py"),
        "import red_cell\nred_cell.register_callback('agent_checkin', 'not_callable')\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let descriptor = runtime
        .script_descriptors()
        .into_iter()
        .find(|s| s.name == "bad_event")
        .expect("script descriptor should exist");
    assert_eq!(descriptor.status, ScriptLoadStatus::Error);
    assert!(
        descriptor.error.as_ref().is_some_and(|e| e.contains("callback must be callable")),
        "error should mention non-callable callback, got: {:?}",
        descriptor.error,
    );
}
#[test]
fn register_callback_rejects_unsupported_event_type() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("bad_event_type.py"),
        "import red_cell\nred_cell.register_callback('no_such_event', lambda: None)\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let descriptor = runtime
        .script_descriptors()
        .into_iter()
        .find(|s| s.name == "bad_event_type")
        .expect("script descriptor should exist");
    assert_eq!(descriptor.status, ScriptLoadStatus::Error);
    assert!(
        descriptor.error.as_ref().is_some_and(|e| e.contains("unsupported client callback")),
        "error should mention unsupported event type, got: {:?}",
        descriptor.error,
    );
}
#[test]
fn register_command_rejects_malformed_options_item() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    // Options list contains a string instead of a dict.
    write_script(
        &temp_dir.path().join("bad_opts.py"),
        "import red_cell\nred_cell.register_command('oops', lambda a, b: None, options=['not_a_dict'])\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert!(
        runtime.command_names().is_empty(),
        "no command should be registered with a malformed options list"
    );
    let descriptor = runtime
        .script_descriptors()
        .into_iter()
        .find(|s| s.name == "bad_opts")
        .expect("script descriptor should exist");
    assert_eq!(descriptor.status, ScriptLoadStatus::Error);
    assert!(
        descriptor.error.as_ref().is_some_and(|e| e.contains("each option must be a dict")),
        "error should mention dict requirement, got: {:?}",
        descriptor.error,
    );
}
#[test]
fn register_command_rejects_unknown_option_type() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("bad_type.py"),
        "import red_cell\nred_cell.register_command(\n    'oops', lambda a, b: None,\n    options=[{'name': 'x', 'type': 'quaternion'}]\n)\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert!(
        runtime.command_names().is_empty(),
        "no command should be registered with an unknown option type"
    );
    let descriptor = runtime
        .script_descriptors()
        .into_iter()
        .find(|s| s.name == "bad_type")
        .expect("script descriptor should exist");
    assert_eq!(descriptor.status, ScriptLoadStatus::Error);
    assert!(
        descriptor.error.as_ref().is_some_and(|e| e.contains("unknown option type `quaternion`")),
        "error should mention unknown option type, got: {:?}",
        descriptor.error,
    );
}
#[test]
fn register_command_rejects_option_missing_name() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("no_name.py"),
        "import red_cell\nred_cell.register_command(\n    'oops', lambda a, b: None,\n    options=[{'type': 'string'}]\n)\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert!(
        runtime.command_names().is_empty(),
        "no command should be registered when option name is missing"
    );
    let descriptor = runtime
        .script_descriptors()
        .into_iter()
        .find(|s| s.name == "no_name")
        .expect("script descriptor should exist");
    assert_eq!(descriptor.status, ScriptLoadStatus::Error);
    assert!(
        descriptor.error.as_ref().is_some_and(|e| e.contains("option is missing 'name'")),
        "error should mention missing name, got: {:?}",
        descriptor.error,
    );
}
#[test]
fn havocui_register_command_rejects_unknown_option_type() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("ui_bad_type.py"),
        "import havocui\nhavocui.RegisterCommand(\n    'oops', 'desc',\n    [{'name': 'x', 'type': 'imaginary'}],\n    lambda: None\n)\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert!(
        runtime.command_names().is_empty(),
        "no command should be registered with an unknown option type via havocui"
    );
    let descriptor = runtime
        .script_descriptors()
        .into_iter()
        .find(|s| s.name == "ui_bad_type")
        .expect("script descriptor should exist");
    assert_eq!(descriptor.status, ScriptLoadStatus::Error);
    assert!(
        descriptor.error.as_ref().is_some_and(|e| e.contains("unknown option type `imaginary`")),
        "error should mention unknown option type, got: {:?}",
        descriptor.error,
    );
}
#[test]
fn register_command_rejects_non_iterable_options() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("opts_int.py"),
        "import red_cell\nred_cell.register_command('oops', lambda a, b: None, options=999)\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert!(
        runtime.command_names().is_empty(),
        "no command should be registered when options is not iterable"
    );
    let descriptor = runtime
        .script_descriptors()
        .into_iter()
        .find(|s| s.name == "opts_int")
        .expect("script descriptor should exist");
    assert_eq!(descriptor.status, ScriptLoadStatus::Error);
    assert!(
        descriptor.error.as_ref().is_some_and(|e| e.contains("options must be a list")),
        "error should mention list requirement, got: {:?}",
        descriptor.error,
    );
}
#[test]
fn command_history_evicts_oldest_entries_at_capacity() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("hist_cap.txt");

    // Register a command that writes the history snapshot to a file.
    let script = format!(
        "import json\nimport pathlib\nimport red_cell\n\
        def cmd(context):\n    pathlib.Path({output:?}).write_text(json.dumps(context.history))\n\
        red_cell.register_command('hcap', cmd)\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("hcap.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("DEADBEEF"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let total_invocations = MAX_COMMAND_HISTORY + 5; // 105

    // Invoke the command 105 times to overflow the history buffer.
    for i in 0..total_invocations {
        std::fs::remove_file(&output_path).ok();
        runtime
            .execute_registered_command("DEADBEEF", &format!("hcap call-{i}"))
            .unwrap_or_else(|e| panic!("invocation {i} should run: {e}"));
        let _ = wait_for_file_contents(&output_path)
            .unwrap_or_else(|| panic!("output should be written for invocation {i}"));
    }

    // Invoke once more (the 106th call) — the snapshot should contain exactly
    // MAX_COMMAND_HISTORY entries, with the oldest 5 evicted.
    std::fs::remove_file(&output_path).ok();
    runtime
        .execute_registered_command("DEADBEEF", "hcap final")
        .unwrap_or_else(|e| panic!("final invocation should run: {e}"));
    let final_output = wait_for_file_contents(&output_path)
        .unwrap_or_else(|| panic!("output should be written for final invocation"));
    let history: Vec<String> = serde_json::from_str(&final_output)
        .unwrap_or_else(|e| panic!("history should be valid JSON: {e}"));

    assert_eq!(
        history.len(),
        MAX_COMMAND_HISTORY,
        "history should be capped at {MAX_COMMAND_HISTORY}, got {}",
        history.len(),
    );

    // The oldest entries (call-0 through call-4) should have been evicted.
    for evicted_idx in 0..5 {
        let evicted = format!("hcap call-{evicted_idx}");
        assert!(!history.iter().any(|h| *h == evicted), "entry {evicted} should have been evicted",);
    }

    // The first entry in the snapshot should be call-5 (the 6th invocation).
    assert_eq!(history[0], "hcap call-5", "first history entry should be call-5 after eviction",);

    // The last entry should be the 105th invocation (call-104).
    assert_eq!(
        history[MAX_COMMAND_HISTORY - 1],
        format!("hcap call-{}", total_invocations - 1),
        "last history entry should be the most recent invocation before the final call",
    );
}
