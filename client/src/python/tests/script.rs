//! Script watchdog timeout and `KeyboardInterrupt` injection.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::super::*;
use super::helpers::*;

#[test]
fn set_script_timeout_updates_stored_value() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));
    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));

    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    // Default is 10 s.
    assert_eq!(
        runtime.inner.api_state.script_timeout_secs.load(std::sync::atomic::Ordering::Relaxed),
        DEFAULT_SCRIPT_TIMEOUT_SECS,
    );

    runtime.set_script_timeout(30);
    assert_eq!(
        runtime.inner.api_state.script_timeout_secs.load(std::sync::atomic::Ordering::Relaxed),
        30,
    );
}
#[test]
fn timeout_interrupts_infinite_loop_in_registered_command() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));

    write_script(
        &temp_dir.path().join("loopy.py"),
        "import red_cell, sys\ndef loopy():\n    sys.stdout.write('before\\n')\n    sys.stdout.flush()\n    while True:\n        pass\n    sys.stdout.write('after\\n')\nred_cell.register_command('loopy', loopy)\n",
    );

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    // Set a 1-second timeout so the test is fast.
    runtime.set_script_timeout(1);

    // Dispatch the command — it should return (interrupted) rather than hang.
    let started = Instant::now();
    let result = runtime.execute_registered_command("agent-0", "loopy");
    let elapsed = started.elapsed();

    // The command must complete well within 5 s (generous upper bound).
    assert!(
        elapsed < Duration::from_secs(5),
        "command dispatch blocked for {elapsed:?}; expected interrupt within 5 s"
    );

    // The callback raised KeyboardInterrupt so execute_registered_command
    // returns Err (CommandFailed) — not Ok.
    assert!(result.is_err(), "expected Err from timed-out callback, got Ok");

    // "before" must have been written; "after" must not.
    assert!(wait_for_output(&runtime, "before"), "'before' should appear before the loop");
    let any_after = runtime.script_output().iter().any(|e| e.text.contains("after"));
    assert!(!any_after, "'after' should not appear — loop must have been interrupted");
}
#[test]
fn timeout_interrupts_infinite_loop_in_agent_checkin_callback() {
    let _guard = lock_mutex(&TEST_GUARD);
    let temp_dir = TempDir::new().unwrap_or_else(|error| panic!("tempdir should succeed: {error}"));

    // Script 1: loops indefinitely in the checkin callback.
    write_script(
        &temp_dir.path().join("hang_checkin.py"),
        "import red_cell, sys\ndef on_checkin(agent_id):\n    sys.stdout.write('checkin_before\\n')\n    sys.stdout.flush()\n    while True:\n        pass\nred_cell.on_agent_checkin(on_checkin)\n",
    );
    // Script 2: registers a fast command so we can verify the thread recovers.
    write_script(
        &temp_dir.path().join("recover.py"),
        "import red_cell, sys\ndef ping():\n    sys.stdout.write('pong\\n')\nred_cell.register_command('ping', ping)\n",
    );

    let app_state = Arc::new(Mutex::new(AppState::new("wss://127.0.0.1:40056/havoc/".to_owned())));
    let runtime = PythonRuntime::initialize(app_state, temp_dir.path().to_path_buf())
        .unwrap_or_else(|error| panic!("python runtime should initialize: {error}"));

    // 1-second watchdog so this test finishes quickly.
    runtime.set_script_timeout(1);

    // Dispatch the looping checkin callback (fire-and-forget).
    runtime
        .emit_agent_checkin("DEADBEEF".to_owned())
        .unwrap_or_else(|error| panic!("emit should succeed: {error}"));

    // Wait until the callback has started (written its marker).
    assert!(
        wait_for_output(&runtime, "checkin_before"),
        "'checkin_before' should appear before the loop"
    );

    // Give the watchdog time to fire (timeout is 1 s; allow 3 s total slack).
    thread::sleep(Duration::from_millis(1500));

    // The Python thread must now be unblocked — execute a fast command.
    let result = runtime.execute_registered_command("agent-0", "ping");
    assert!(
        result.is_ok(),
        "Python thread should be responsive after watchdog interrupt; got {result:?}"
    );
    assert!(wait_for_output(&runtime, "pong"), "'pong' should appear from recovery command");
}
