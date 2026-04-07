//! Core runtime, script lifecycle, output capture, and thread-unavailable regressions.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

use super::super::*;
use super::helpers::*;

#[test]
fn lock_mutex_recovers_from_poison() {
    let m = Mutex::new(42u32);
    let _ = std::panic::catch_unwind(|| {
        let _g = m.lock().expect("lock for poison test");
        panic!("intentional test poison");
    });
    assert!(m.is_poisoned());
    let guard = lock_mutex(&m);
    assert_eq!(*guard, 42);
}
#[test]
fn zombie_runtime_emit_agent_checkin_returns_thread_unavailable() {
    let _guard = lock_mutex(&TEST_GUARD);
    let runtime = PythonRuntime::new_zombie_for_test();

    let result = runtime.emit_agent_checkin("DEADBEEF".to_owned());

    assert!(matches!(result, Err(PythonRuntimeError::ThreadUnavailable)));
}
#[test]
fn zombie_runtime_emit_loot_captured_returns_thread_unavailable() {
    let _guard = lock_mutex(&TEST_GUARD);
    let runtime = PythonRuntime::new_zombie_for_test();

    let result = runtime.emit_loot_captured(sample_loot_item(
        "DEADBEEF",
        crate::transport::LootKind::Other,
        "notes.txt",
        Some("c2FtcGxl"),
    ));

    assert!(matches!(result, Err(PythonRuntimeError::ThreadUnavailable)));
}
#[test]
fn zombie_runtime_execute_registered_command_returns_thread_unavailable() {
    let _guard = lock_mutex(&TEST_GUARD);
    let runtime = PythonRuntime::new_zombie_for_test();

    let result = runtime.execute_registered_command("DEADBEEF", "zombie");

    assert!(matches!(result, Err(PythonRuntimeError::ThreadUnavailable)));
}
#[test]
fn runtime_loads_scripts_and_registers_commands() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("sample.py"),
        "import red_cell\nred_cell.register_command('demo', lambda: None)\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert_eq!(runtime.command_names(), vec!["demo".to_owned()]);
    assert_eq!(
        runtime.script_descriptors(),
        vec![ScriptDescriptor {
            name: "sample".to_owned(),
            path: temp_dir.path().join("sample.py"),
            status: ScriptLoadStatus::Loaded,
            error: None,
            registered_commands: vec!["demo".to_owned()],
            registered_command_count: 1,
        }]
    );
}
#[test]
fn runtime_isolates_bad_scripts() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("good.py"),
        "import red_cell\nred_cell.register_command('good', lambda: None)\n",
    );
    write_script(&temp_dir.path().join("bad.py"), "raise RuntimeError('boom')\n");
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert_eq!(runtime.command_names(), vec!["good".to_owned()]);
    assert_eq!(runtime.script_descriptors().len(), 2);
    assert!(
        runtime
            .script_descriptors()
            .iter()
            .find(|script| script.name == "bad")
            .and_then(|script| script.error.as_ref())
            .is_some_and(|error| error.contains("boom"))
    );
}
#[test]
fn runtime_can_reload_and_unload_scripts() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let script_path = temp_dir.path().join("sample.py");
    write_script(
        &script_path,
        "import havocui\nimport red_cell\n\
def on_checkin(agent):\n    print('checkin:' + agent.id)\n\
def render():\n    havocui.SetTabLayout('Status', 'operator layout')\n\
red_cell.register_command('demo', lambda: None)\n\
red_cell.on_agent_checkin(on_checkin)\n\
havocui.CreateTab('Status', render)\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));
    assert_eq!(runtime.command_names(), vec!["__tab__ status".to_owned(), "demo".to_owned()]);
    assert_eq!(
        runtime.script_tabs(),
        vec![ScriptTabDescriptor {
            title: "Status".to_owned(),
            script_name: "sample".to_owned(),
            layout: String::new(),
            has_callback: true,
        }]
    );

    runtime
        .emit_agent_checkin("00ABCDEF".to_owned())
        .unwrap_or_else(|error| panic!("agent checkin dispatch should succeed: {error}"));
    assert!(wait_for_output_occurrences(&runtime, "checkin:00ABCDEF", 1));

    write_script(
        &script_path,
        "import havocui\nimport red_cell\n\
def on_checkin(agent):\n    print('checkin:' + agent.id)\n\
def render():\n    havocui.SetTabLayout('Status', 'reloaded layout')\n\
red_cell.register_command('updated', lambda: None)\n\
red_cell.on_agent_checkin(on_checkin)\n\
havocui.CreateTab('Status', render)\n",
    );
    runtime
        .reload_script("sample")
        .unwrap_or_else(|error| panic!("reload should succeed: {error}"));
    assert_eq!(runtime.command_names(), vec!["__tab__ status".to_owned(), "updated".to_owned()]);
    assert_eq!(
        runtime.script_tabs(),
        vec![ScriptTabDescriptor {
            title: "Status".to_owned(),
            script_name: "sample".to_owned(),
            layout: String::new(),
            has_callback: true,
        }]
    );
    runtime
        .emit_agent_checkin("00ABCDEF".to_owned())
        .unwrap_or_else(|error| panic!("agent checkin dispatch should succeed: {error}"));
    assert!(
        wait_for_output_occurrences(&runtime, "checkin:00ABCDEF", 2),
        "reload should register exactly one active callback"
    );

    runtime
        .unload_script("sample")
        .unwrap_or_else(|error| panic!("unload should succeed: {error}"));
    assert!(runtime.command_names().is_empty());
    assert!(runtime.script_tabs().is_empty(), "unload should remove script tabs");

    let output_count_before_unload_emit = output_occurrences(&runtime, "checkin:00ABCDEF");
    runtime
        .emit_agent_checkin("00ABCDEF".to_owned())
        .unwrap_or_else(|error| panic!("agent checkin dispatch should succeed: {error}"));
    thread::sleep(Duration::from_millis(150));
    assert_eq!(
        output_occurrences(&runtime, "checkin:00ABCDEF"),
        output_count_before_unload_emit,
        "unload should remove agent checkin callbacks"
    );
    assert!(
        runtime
            .script_descriptors()
            .iter()
            .find(|script| script.name == "sample")
            .is_some_and(|script| script.status == ScriptLoadStatus::Unloaded)
    );
}
#[test]
fn runtime_captures_script_output() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("chatty.py"),
        "import sys\nprint('hello from stdout')\nprint('hello from stderr', file=sys.stderr)\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert!(wait_for_output(&runtime, "hello from stdout"));
    assert!(wait_for_output(&runtime, "hello from stderr"));
}
#[test]
fn execute_registered_command_returns_false_for_unknown_command() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("demo.py"),
        "import red_cell\nred_cell.register_command('demo', lambda agent, args: 'ok')\n",
    );

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let executed = runtime
        .execute_registered_command("00ABCDEF", "unknown_command")
        .unwrap_or_else(|error| panic!("execute_registered_command should not error: {error}"));

    assert!(!executed, "unknown command should return false");
    assert!(
        runtime.script_output().is_empty(),
        "no output should be generated for an unknown command"
    );
}
#[test]
fn havocui_tabs_are_registered_and_can_refresh_layouts() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let script = "import havocui\n\
def render():\n    havocui.SetTabLayout('Status', 'operator layout')\n\
havocui.CreateTab('Status', render)\n";
    write_script(&temp_dir.path().join("tabbed.py"), script);
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert_eq!(
        runtime.script_tabs(),
        vec![ScriptTabDescriptor {
            title: "Status".to_owned(),
            script_name: "tabbed".to_owned(),
            layout: String::new(),
            has_callback: true,
        }]
    );

    runtime
        .activate_tab("Status")
        .unwrap_or_else(|error| panic!("tab activation should succeed: {error}"));

    assert_eq!(
        runtime.script_tabs(),
        vec![ScriptTabDescriptor {
            title: "Status".to_owned(),
            script_name: "tabbed".to_owned(),
            layout: "operator layout".to_owned(),
            has_callback: true,
        }]
    );
}
#[test]
fn havocui_create_tab_rejects_empty_title() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));

    // Script tries to create a tab with a whitespace-only title.
    let script = "import havocui\n\
        try:\n\
        \x20   havocui.CreateTab('   ')\n\
        except ValueError as e:\n\
        \x20   print(f'caught: {e}')\n";
    write_script(&temp_dir.path().join("empty_tab.py"), script);
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    // The tab set must remain empty — the create call was rejected.
    assert!(runtime.script_tabs().is_empty(), "empty-title tab should not be registered");
    // The script should have caught the ValueError.
    assert!(
        wait_for_output(&runtime, "caught: tab title cannot be empty"),
        "script should log the caught ValueError"
    );
}
#[test]
fn havocui_set_tab_layout_rejects_uncreated_tab() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));

    // Script calls SetTabLayout on a tab that was never created.
    let script = "import havocui\n\
        try:\n\
        \x20   havocui.SetTabLayout('Ghost', '<html></html>')\n\
        except ValueError as e:\n\
        \x20   print(f'caught: {e}')\n";
    write_script(&temp_dir.path().join("layout_no_tab.py"), script);
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert!(runtime.script_tabs().is_empty(), "no tabs should be registered");
    assert!(
        wait_for_output(&runtime, "caught: havocui tab `Ghost` has not been created"),
        "script should log the caught ValueError for uncreated tab"
    );
}
#[test]
fn havocui_set_tab_layout_rejects_cross_script_mutation() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));

    // First script (alpha) creates a tab named "Dashboard".
    let script_alpha = "import havocui\n\
        havocui.CreateTab('Dashboard')\n";
    write_script(&temp_dir.path().join("alpha.py"), script_alpha);

    // Second script (beta) tries to mutate alpha's tab layout.
    let script_beta = "import havocui\n\
        try:\n\
        \x20   havocui.SetTabLayout('Dashboard', 'evil layout')\n\
        except ValueError as e:\n\
        \x20   print(f'caught: {e}')\n";
    write_script(&temp_dir.path().join("beta.py"), script_beta);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    // Alpha's tab should still exist with an empty layout (never mutated).
    let tabs = runtime.script_tabs();
    assert_eq!(tabs.len(), 1, "only alpha's tab should be registered");
    assert_eq!(tabs[0].title, "Dashboard");
    assert_eq!(tabs[0].script_name, "alpha");
    assert_eq!(
        tabs[0].layout, "",
        "layout must remain empty — beta's mutation should have been rejected"
    );

    // Beta should have caught the cross-script error.
    assert!(
        wait_for_output(&runtime, "caught: havocui tab `Dashboard` belongs to a different script"),
        "script should log the caught ValueError for cross-script mutation"
    );
}
#[test]
fn script_output_evicts_oldest_entries_at_capacity() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));

    // Generate a script that creates 520 distinct output entries by alternating
    // between stdout and stderr (preventing coalescing of consecutive entries).
    let total_entries = MAX_SCRIPT_OUTPUT_ENTRIES + 8; // 520
    let script = format!(
        "import sys\nfor i in range({total_entries}):\n\
         \x20   if i % 2 == 0:\n\
         \x20       sys.stdout.write(f'out-{{i}}\\n')\n\
         \x20       sys.stdout.flush()\n\
         \x20   else:\n\
         \x20       sys.stderr.write(f'err-{{i}}\\n')\n\
         \x20       sys.stderr.flush()\n",
    );
    write_script(&temp_dir.path().join("flood.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    // Wait until the last entry appears in the output log.
    let last_marker = format!("err-{}", total_entries - 1);
    assert!(wait_for_output(&runtime, &last_marker), "last output entry should appear",);

    let output = runtime.script_output();
    assert!(
        output.len() <= MAX_SCRIPT_OUTPUT_ENTRIES,
        "output log should be capped at {MAX_SCRIPT_OUTPUT_ENTRIES}, got {}",
        output.len(),
    );

    // The oldest entries (indices 0..8) should have been evicted.
    let has_evicted_entry = output.iter().any(|e| e.text.contains("out-0\n"));
    assert!(!has_evicted_entry, "oldest entry (out-0) should have been evicted",);

    // The newest entries should still be present.
    let has_newest = output.iter().any(|e| e.text.contains(&last_marker));
    assert!(has_newest, "newest entry should still be present");
}
#[test]
fn execute_registered_command_captures_callback_exception() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let script = "import red_cell\n\
def boom(agent, args):\n    raise RuntimeError('plugin exploded')\n\
red_cell.register_command('boom', boom)\n";
    write_script(&temp_dir.path().join("boom.py"), script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let result = runtime.execute_registered_command("00ABCDEF", "boom");
    assert!(
        result.is_err(),
        "execute_registered_command should return an error when the callback raises"
    );
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("plugin exploded"),
        "error should contain the exception message, got: {error_message}"
    );

    // The runtime should still be functional after the exception.
    let second = runtime.execute_registered_command("00ABCDEF", "boom");
    assert!(second.is_err(), "callback should still raise on second invocation");
}
#[test]
fn reload_script_returns_error_for_unknown_script() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let result = runtime.reload_script("nonexistent_plugin");
    assert!(result.is_err(), "reload_script should return an error for an unknown script name");
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("nonexistent_plugin"),
        "error should mention the script name, got: {error_message}"
    );
}
#[test]
fn unload_script_twice_is_idempotent() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("ephemeral.py"),
        "import red_cell\nred_cell.register_command('temp', lambda: None)\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert_eq!(runtime.command_names(), vec!["temp".to_owned()]);

    runtime
        .unload_script("ephemeral")
        .unwrap_or_else(|error| panic!("first unload should succeed: {error}"));
    assert!(runtime.command_names().is_empty());
    assert!(
        runtime
            .script_descriptors()
            .iter()
            .find(|s| s.name == "ephemeral")
            .is_some_and(|s| s.status == ScriptLoadStatus::Unloaded)
    );

    // Second unload of the same script should also succeed.
    runtime
        .unload_script("ephemeral")
        .unwrap_or_else(|error| panic!("second unload should succeed (idempotent): {error}"));
    assert!(
        runtime
            .script_descriptors()
            .iter()
            .find(|s| s.name == "ephemeral")
            .is_some_and(|s| s.status == ScriptLoadStatus::Unloaded)
    );
}
#[test]
fn load_script_registers_command_and_descriptor() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    // Initialize runtime with an empty directory — no scripts loaded yet.
    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));
    assert!(runtime.command_names().is_empty(), "no commands before load");
    assert!(runtime.script_descriptors().is_empty(), "no descriptors before load");

    // Write a script and load it via load_script.
    let script_path = temp_dir.path().join("plugin.py");
    write_script(
        &script_path,
        "import red_cell\nred_cell.register_command('greet', lambda: None)\n",
    );
    runtime
        .load_script(script_path.clone())
        .unwrap_or_else(|error| panic!("load_script should succeed: {error}"));

    assert_eq!(runtime.command_names(), vec!["greet".to_owned()]);
    assert_eq!(
        runtime.script_descriptors(),
        vec![ScriptDescriptor {
            name: "plugin".to_owned(),
            path: script_path,
            status: ScriptLoadStatus::Loaded,
            error: None,
            registered_commands: vec!["greet".to_owned()],
            registered_command_count: 1,
        }]
    );
}
#[test]
fn load_script_nonexistent_path_returns_error() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let result = runtime.load_script(temp_dir.path().join("nonexistent.py"));
    assert!(result.is_err(), "load_script with a nonexistent path should return an error");
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("nonexistent"),
        "error should reference the missing file, got: {error_message}"
    );
}
#[test]
fn load_script_twice_is_idempotent() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let script_path = temp_dir.path().join("twice.py");
    write_script(&script_path, "import red_cell\nred_cell.register_command('cmd', lambda: None)\n");

    runtime
        .load_script(script_path.clone())
        .unwrap_or_else(|error| panic!("first load should succeed: {error}"));
    runtime
        .load_script(script_path.clone())
        .unwrap_or_else(|error| panic!("second load should succeed: {error}"));

    // Command should appear exactly once — not duplicated.
    assert_eq!(runtime.command_names(), vec!["cmd".to_owned()]);
    assert_eq!(
        runtime.script_descriptors().len(),
        1,
        "only one script descriptor should exist after loading twice"
    );
    assert_eq!(runtime.script_descriptors()[0].registered_command_count, 1);
}
#[test]
fn emit_agent_checkin_returns_thread_unavailable_on_zombie_runtime() {
    let _guard = lock_mutex(&TEST_GUARD);
    let runtime = PythonRuntime::new_zombie_for_test();
    let result = runtime.emit_agent_checkin("dead-agent-id".to_owned());
    assert!(
        matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
        "expected ThreadUnavailable, got: {result:?}"
    );
}
#[test]
fn emit_command_response_returns_thread_unavailable_on_zombie_runtime() {
    let _guard = lock_mutex(&TEST_GUARD);
    let runtime = PythonRuntime::new_zombie_for_test();
    let result = runtime.emit_command_response(
        "dead-agent".to_owned(),
        "task-1".to_owned(),
        "output".to_owned(),
    );
    assert!(
        matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
        "expected ThreadUnavailable, got: {result:?}"
    );
}
#[test]
fn emit_loot_captured_returns_thread_unavailable_on_zombie_runtime() {
    let _guard = lock_mutex(&TEST_GUARD);
    let runtime = PythonRuntime::new_zombie_for_test();
    let loot = sample_loot_item("dead-agent", crate::transport::LootKind::Credential, "hash", None);
    let result = runtime.emit_loot_captured(loot);
    assert!(
        matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
        "expected ThreadUnavailable, got: {result:?}"
    );
}
#[test]
fn emit_listener_changed_returns_thread_unavailable_on_zombie_runtime() {
    let _guard = lock_mutex(&TEST_GUARD);
    let runtime = PythonRuntime::new_zombie_for_test();
    let result = runtime.emit_listener_changed("https-443".to_owned(), "started".to_owned());
    assert!(
        matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
        "expected ThreadUnavailable, got: {result:?}"
    );
}
#[test]
fn execute_registered_command_returns_thread_unavailable_on_zombie_runtime() {
    let _guard = lock_mutex(&TEST_GUARD);
    // new_zombie_for_test registers a "zombie" command so match_registered_command
    // succeeds and the send path is exercised.
    let runtime = PythonRuntime::new_zombie_for_test();
    let result = runtime.execute_registered_command("dead-agent", "zombie");
    assert!(
        matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
        "expected ThreadUnavailable, got: {result:?}"
    );
}
#[test]
fn activate_tab_returns_thread_unavailable_on_zombie_runtime() {
    let _guard = lock_mutex(&TEST_GUARD);
    let runtime = PythonRuntime::new_zombie_for_test();
    let result = runtime.activate_tab("some-tab");
    assert!(
        matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
        "expected ThreadUnavailable, got: {result:?}"
    );
}
#[test]
fn load_script_returns_thread_unavailable_on_zombie_runtime() {
    let _guard = lock_mutex(&TEST_GUARD);
    let runtime = PythonRuntime::new_zombie_for_test();
    let result = runtime.load_script("/tmp/nonexistent.py".into());
    assert!(
        matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
        "expected ThreadUnavailable, got: {result:?}"
    );
}
#[test]
fn reload_script_returns_thread_unavailable_on_zombie_runtime() {
    let _guard = lock_mutex(&TEST_GUARD);
    let runtime = PythonRuntime::new_zombie_for_test();
    let result = runtime.reload_script("some_script");
    assert!(
        matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
        "expected ThreadUnavailable, got: {result:?}"
    );
}
#[test]
fn unload_script_returns_thread_unavailable_on_zombie_runtime() {
    let _guard = lock_mutex(&TEST_GUARD);
    let runtime = PythonRuntime::new_zombie_for_test();
    let result = runtime.unload_script("some_script");
    assert!(
        matches!(result, Err(PythonRuntimeError::ThreadUnavailable)),
        "expected ThreadUnavailable, got: {result:?}"
    );
}
#[test]
fn script_output_returns_empty_before_any_output() {
    let _guard = lock_mutex(&TEST_GUARD);
    let runtime = PythonRuntime::new_zombie_for_test();
    assert!(
        runtime.script_output().is_empty(),
        "script_output should be empty before any script emits"
    );
}
#[test]
fn script_output_captures_correct_stream_and_text() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("streams.py"),
        "import sys\nprint('out-marker')\nprint('err-marker', file=sys.stderr)\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert!(wait_for_output(&runtime, "out-marker"), "stdout entry should appear");
    assert!(wait_for_output(&runtime, "err-marker"), "stderr entry should appear");

    let entries = runtime.script_output();
    let stdout_entry =
        entries.iter().find(|e| e.text.contains("out-marker")).expect("stdout entry missing");
    assert_eq!(stdout_entry.stream, ScriptOutputStream::Stdout);
    assert_eq!(stdout_entry.script_name, "streams");

    let stderr_entry =
        entries.iter().find(|e| e.text.contains("err-marker")).expect("stderr entry missing");
    assert_eq!(stderr_entry.stream, ScriptOutputStream::Stderr);
    assert_eq!(stderr_entry.script_name, "streams");
}
#[test]
fn script_tabs_returns_empty_before_any_createtab_call() {
    let _guard = lock_mutex(&TEST_GUARD);
    let runtime = PythonRuntime::new_zombie_for_test();
    assert!(runtime.script_tabs().is_empty(), "script_tabs should be empty before any CreateTab");
}
#[test]
fn script_tabs_is_empty_after_unloading_registering_script() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("tabscript.py"),
        "import havocui\ndef render(): pass\nhavocui.CreateTab('Panel', render)\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    assert_eq!(
        runtime.script_tabs(),
        vec![ScriptTabDescriptor {
            title: "Panel".to_owned(),
            script_name: "tabscript".to_owned(),
            layout: String::new(),
            has_callback: true,
        }],
        "tab should be present after script load"
    );

    runtime
        .unload_script("tabscript")
        .unwrap_or_else(|error| panic!("unload should succeed: {error}"));

    assert!(
        runtime.script_tabs().is_empty(),
        "script_tabs should be empty after unloading the registering script"
    );
}
