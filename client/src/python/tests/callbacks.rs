//! Event dispatch: agent check-in, command response, loot, listeners, and concurrent output.

use std::sync::Arc;

use tempfile::TempDir;

use super::super::*;
use super::helpers::*;

#[test]
fn runtime_dispatches_agent_checkin_callbacks() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("checkin.txt");
    let script = format!(
        "import pathlib\nimport red_cell\n\
def on_checkin(agent):\n    pathlib.Path({output:?}).write_text(agent.info['hostname'])\n\
red_cell.on_agent_checkin(on_checkin)\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("checkin.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    runtime
        .emit_agent_checkin("00ABCDEF".to_owned())
        .unwrap_or_else(|error| panic!("agent checkin dispatch should succeed: {error}"));

    assert_eq!(wait_for_file_contents(&output_path).as_deref(), Some("wkstn-01"));
}
#[test]
fn havoc_event_and_havocui_modules_are_compatible() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("event.txt");
    let script = format!(
        "import pathlib\nimport havoc\nimport havocui\n\
event = havoc.Event('events')\n\
def on_new_session(identifier):\n    pathlib.Path({output:?}).write_text(identifier)\n    havocui.MessageBox('new session for ' + identifier)\n\
event.OnNewSession(on_new_session)\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("havoc_ui.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    runtime
        .emit_agent_checkin("00ABCDEF".to_owned())
        .unwrap_or_else(|error| panic!("havoc event dispatch should succeed: {error}"));

    assert_eq!(wait_for_file_contents(&output_path).as_deref(), Some("00ABCDEF"));
    assert!(wait_for_output(&runtime, "new session for 00ABCDEF"));
}
#[test]
fn runtime_dispatches_command_response_callbacks() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("response.txt");
    let script = format!(
        "import pathlib\nimport red_cell\n\
def on_resp(agent_id, task_id, output):\n    pathlib.Path({output:?}).write_text(agent_id + ':' + task_id + ':' + output)\n\
red_cell.on_command_response(on_resp)\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("resp.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    runtime
        .emit_command_response(
            "AABBCCDD".to_owned(),
            "TASKID01".to_owned(),
            "whoami output".to_owned(),
        )
        .unwrap_or_else(|error| panic!("emit_command_response should succeed: {error}"));

    assert_eq!(
        wait_for_file_contents(&output_path).as_deref(),
        Some("AABBCCDD:TASKID01:whoami output")
    );
}
#[test]
fn runtime_dispatches_loot_captured_callbacks() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("loot.txt");
    let script = format!(
        "import pathlib\nimport red_cell\n\
def on_loot(agent_id, loot):\n    pathlib.Path({output:?}).write_text(agent_id + ':' + loot.type + ':' + loot.name)\n\
red_cell.on_loot_captured(on_loot)\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("loot.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    let loot_item = sample_loot_item(
        "AABBCCDD",
        crate::transport::LootKind::Credential,
        "domain\\user:pass",
        Some("dXNlcjpwYXNz"),
    );
    runtime
        .emit_loot_captured(loot_item)
        .unwrap_or_else(|error| panic!("emit_loot_captured should succeed: {error}"));

    assert_eq!(
        wait_for_file_contents(&output_path).as_deref(),
        Some("AABBCCDD:Credential:domain\\user:pass")
    );
}
#[test]
fn runtime_dispatches_listener_changed_callbacks() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("listener.txt");
    let script = format!(
        "import pathlib\nimport red_cell\n\
def on_listener(listener_id, action):\n    pathlib.Path({output:?}).write_text(listener_id + ':' + action)\n\
red_cell.on_listener_changed(on_listener)\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("listener_cb.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    runtime
        .emit_listener_changed("https-listener".to_owned(), "start".to_owned())
        .unwrap_or_else(|error| panic!("emit_listener_changed should succeed: {error}"));

    assert_eq!(wait_for_file_contents(&output_path).as_deref(), Some("https-listener:start"));
}
#[test]
fn event_registrar_exposes_new_event_methods() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let output_path = temp_dir.path().join("event_registrar.txt");
    let script = format!(
        "import pathlib\nimport havoc\n\
event = havoc.Event('test')\n\
def on_resp(agent_id, task_id, output):\n    pathlib.Path({output:?}).write_text('resp:' + agent_id)\n\
event.OnCommandResponse(on_resp)\n",
        output = output_path.display().to_string()
    );
    write_script(&temp_dir.path().join("event_reg.py"), &script);

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    runtime
        .emit_command_response("DEADBEEF".to_owned(), String::new(), "output".to_owned())
        .unwrap_or_else(|error| panic!("emit_command_response should succeed: {error}"));

    assert_eq!(wait_for_file_contents(&output_path).as_deref(), Some("resp:DEADBEEF"));
}
#[test]
fn script_output_collects_from_two_concurrent_scripts() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    write_script(
        &temp_dir.path().join("alpha.py"),
        "import red_cell\ndef on_checkin(agent):\n    print('alpha:' + agent.id)\nred_cell.on_agent_checkin(on_checkin)\n",
    );
    write_script(
        &temp_dir.path().join("beta.py"),
        "import red_cell\ndef on_checkin(agent):\n    print('beta:' + agent.id)\nred_cell.on_agent_checkin(on_checkin)\n",
    );
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    {
        let mut state = lock_app_state(&app_state);
        Arc::make_mut(&mut state.agents).push(sample_agent("00ABCDEF"));
    }

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    // Fire two checkin events from separate threads to exercise concurrent output writes.
    let r1 = runtime.clone();
    let r2 = runtime.clone();
    let t1 = thread::spawn(move || {
        r1.emit_agent_checkin("00ABCDEF".to_owned())
            .unwrap_or_else(|error| panic!("checkin dispatch should succeed: {error}"));
    });
    let t2 = thread::spawn(move || {
        r2.emit_agent_checkin("00ABCDEF".to_owned())
            .unwrap_or_else(|error| panic!("checkin dispatch should succeed: {error}"));
    });
    t1.join().unwrap_or_else(|_| panic!("thread 1 should not panic"));
    t2.join().unwrap_or_else(|_| panic!("thread 2 should not panic"));

    // Each script fires once per emit call, and we fired two; expect at least one from each.
    assert!(
        wait_for_output_occurrences(&runtime, "alpha:00ABCDEF", 1),
        "alpha script output should appear"
    );
    assert!(
        wait_for_output_occurrences(&runtime, "beta:00ABCDEF", 1),
        "beta script output should appear"
    );
}
