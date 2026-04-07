//! Script loading, execution, watchdog, and Python thread management.

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::Duration;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use tracing::warn;

use super::{
    PythonApiState, PythonThreadCommand, install_api_module, install_output_capture, lock_mutex,
};

/// Inject a `KeyboardInterrupt` into the Python thread identified by
/// `thread_id` using `ctypes.pythonapi.PyThreadState_SetAsyncExc`.
///
/// CPython releases the GIL every `sys.getswitchinterval()` seconds
/// (default 5 ms) even during tight pure-Python loops, so the caller
/// will acquire the GIL at most a few milliseconds after calling this.
///
/// Returns `Ok(())` if the interrupt was injected, or a descriptive
/// error if the `ctypes` call could not be made.
pub(super) fn inject_keyboard_interrupt(py: Python<'_>, thread_id: u64) -> PyResult<()> {
    let ctypes = py.import("ctypes")?;
    let pythonapi = ctypes.getattr("pythonapi")?;
    let thread_id_obj = ctypes.getattr("c_ulong")?.call1((thread_id,))?;
    let exc_type = py.import("builtins")?.getattr("KeyboardInterrupt")?;
    let exc_obj = ctypes.getattr("py_object")?.call1((exc_type,))?;
    pythonapi.call_method1("PyThreadState_SetAsyncExc", (thread_id_obj, exc_obj))?;
    Ok(())
}

/// Spawn a watchdog `std::thread` that injects `KeyboardInterrupt` into the
/// Python thread with id `python_thread_id` if the returned `SyncSender` is
/// not sent-to (or dropped) before `timeout` elapses.
///
/// The interrupt is delivered by acquiring the GIL and calling
/// `ctypes.pythonapi.PyThreadState_SetAsyncExc`.  CPython releases the GIL
/// periodically even in tight loops, so the watchdog will unblock within a
/// small multiple of `sys.getswitchinterval()` (≤ 5 ms by default).
///
/// Usage pattern:
/// ```ignore
/// let watchdog = spawn_script_watchdog(timeout, name.clone(), "agent_checkin", thread_id);
/// let result = callback.call0();
/// drop(watchdog); // cancel — callback completed in time
/// ```
pub(super) fn spawn_script_watchdog(
    timeout: Duration,
    script_name: String,
    callback_type: &'static str,
    python_thread_id: u64,
) -> mpsc::SyncSender<()> {
    let (cancel_tx, cancel_rx) = mpsc::sync_channel::<()>(1);
    thread::spawn(move || match cancel_rx.recv_timeout(timeout) {
        // Sender dropped or sent — callback completed before the deadline.
        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
        Err(mpsc::RecvTimeoutError::Timeout) => {
            tracing::error!(
                script = %script_name,
                callback = %callback_type,
                timeout_secs = timeout.as_secs(),
                "python script timed out; injecting KeyboardInterrupt",
            );
            if python_thread_id != 0 {
                // Acquire the GIL — CPython releases it periodically so this
                // will unblock within a few milliseconds even for tight loops.
                Python::with_gil(|py| {
                    if let Err(error) = inject_keyboard_interrupt(py, python_thread_id) {
                        tracing::warn!(%error, "failed to inject KeyboardInterrupt into python thread");
                    }
                });
            }
        }
    });
    cancel_tx
}

pub(super) fn python_thread_main(
    api_state: Arc<PythonApiState>,
    scripts_dir: PathBuf,
    command_rx: Receiver<PythonThreadCommand>,
    ready_tx: SyncSender<Result<(), String>>,
) -> Result<(), String> {
    pyo3::prepare_freethreaded_python();
    if let Err(error) = std::fs::create_dir_all(&scripts_dir) {
        let message =
            format!("failed to create scripts directory {}: {error}", scripts_dir.display());
        let _ = ready_tx.send(Err(message.clone()));
        return Err(message);
    }

    // Record this thread's Python identity so watchdog threads can target it
    // with `ctypes.pythonapi.PyThreadState_SetAsyncExc` when a callback times out.
    let thread_id_result = Python::with_gil(|py| -> PyResult<u64> {
        py.import("threading")?.call_method0("get_ident")?.extract()
    });
    match thread_id_result {
        Ok(id) => api_state.python_thread_id.store(id, Ordering::Relaxed),
        Err(ref error) => {
            tracing::warn!(%error, "could not determine python thread id; script timeouts will not interrupt running callbacks");
        }
    }

    let init_result = Python::with_gil(|py| -> PyResult<()> {
        install_api_module(py)?;
        install_output_capture(py)?;
        load_scripts(py, api_state.as_ref(), &scripts_dir);
        Ok(())
    })
    .map_err(|error| error.to_string());
    match init_result {
        Ok(()) => {
            let _ = ready_tx.send(Ok(()));
        }
        Err(error) => {
            let _ = ready_tx.send(Err(error.clone()));
            return Err(error);
        }
    }

    while let Ok(command) = command_rx.recv() {
        match command {
            PythonThreadCommand::EmitAgentCheckin(agent_id) => {
                Python::with_gil(|py| api_state.invoke_agent_checkin_callbacks(py, &agent_id));
            }
            PythonThreadCommand::EmitCommandResponse { agent_id, task_id, output } => {
                Python::with_gil(|py| {
                    api_state.invoke_command_response_callbacks(py, &agent_id, &task_id, &output);
                });
            }
            PythonThreadCommand::EmitLootCaptured(loot_item) => {
                Python::with_gil(|py| {
                    api_state.invoke_loot_captured_callbacks(py, &loot_item);
                });
            }
            PythonThreadCommand::EmitListenerChanged { name, action } => {
                Python::with_gil(|py| {
                    api_state.invoke_listener_changed_callbacks(py, &name, &action);
                });
            }
            PythonThreadCommand::ActivateTab { title, response_tx } => {
                let result = Python::with_gil(|py| api_state.activate_tab(py, &title));
                let _ = response_tx.send(result);
            }
            PythonThreadCommand::ExecuteRegisteredCommand {
                command_name,
                command_line,
                agent_id,
                arguments,
                response_tx,
            } => {
                let result = Python::with_gil(|py| {
                    api_state.execute_registered_command(
                        py,
                        &command_name,
                        &agent_id,
                        &command_line,
                        &arguments,
                    )
                });
                let _ = response_tx.send(result);
            }
            PythonThreadCommand::LoadScript(path, response_tx) => {
                let result =
                    Python::with_gil(|py| load_script_at_path(py, api_state.as_ref(), &path));
                let _ = response_tx.send(result);
            }
            PythonThreadCommand::ReloadScript(script_name, response_tx) => {
                let result = Python::with_gil(|py| {
                    reload_script_by_name(py, api_state.as_ref(), &script_name)
                });
                let _ = response_tx.send(result);
            }
            PythonThreadCommand::UnloadScript(script_name, response_tx) => {
                let result = Python::with_gil(|py| {
                    unload_script_by_name(py, api_state.as_ref(), &script_name)
                });
                let _ = response_tx.send(result);
            }
            PythonThreadCommand::Shutdown => break,
        }
    }

    Ok(())
}

pub(super) fn load_scripts(py: Python<'_>, api_state: &PythonApiState, scripts_dir: &Path) {
    let mut entries = match std::fs::read_dir(scripts_dir) {
        Ok(entries) => entries.filter_map(Result::ok).collect::<Vec<_>>(),
        Err(error) => {
            warn!(
                path = %scripts_dir.display(),
                error = %error,
                "failed to enumerate client python scripts"
            );
            return;
        }
    };
    entries.sort_by_key(|entry| entry.path());

    if let Ok(sys) = py.import("sys")
        && let Ok(path) = sys.getattr("path")
    {
        let _ = path.call_method1("insert", (0, scripts_dir.display().to_string()));
    }

    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("py") {
            continue;
        }

        if let Err(error) = load_script_at_path(py, api_state, &path) {
            warn!(script = %path.display(), error = %error, "failed to load client python script");
        }
    }
}

pub(super) fn load_script_at_path(
    py: Python<'_>,
    api_state: &PythonApiState,
    path: &Path,
) -> Result<(), String> {
    let script_name = script_name_from_path(path)?;
    api_state.ensure_script_record(&script_name, path.to_path_buf());
    unload_script_bindings(py, api_state, &script_name)?;

    api_state.begin_script_execution(&script_name, Some("script_load"));
    let result = load_script(py, path, &script_name).map_err(|error| error.to_string());
    api_state.end_script_execution();

    match result {
        Ok(()) => {
            api_state.mark_script_loaded(&script_name);
            Ok(())
        }
        Err(error) => {
            api_state.mark_script_error(&script_name, error.clone());
            Err(error)
        }
    }
}

pub(super) fn reload_script_by_name(
    py: Python<'_>,
    api_state: &PythonApiState,
    script_name: &str,
) -> Result<(), String> {
    let path = lock_mutex(&api_state.script_records)
        .get(script_name)
        .map(|record| record.path.clone())
        .ok_or_else(|| format!("script `{script_name}` is not known to the runtime"))?;
    load_script_at_path(py, api_state, &path)
}

pub(super) fn unload_script_by_name(
    py: Python<'_>,
    api_state: &PythonApiState,
    script_name: &str,
) -> Result<(), String> {
    if !lock_mutex(&api_state.script_records).contains_key(script_name) {
        return Err(format!("script `{script_name}` is not known to the runtime"));
    }
    unload_script_bindings(py, api_state, script_name)?;
    api_state.mark_script_unloaded(script_name);
    Ok(())
}

fn unload_script_bindings(
    py: Python<'_>,
    api_state: &PythonApiState,
    script_name: &str,
) -> Result<(), String> {
    api_state.clear_script_bindings(script_name);
    let sys = py.import("sys").map_err(|error| error.to_string())?;
    let modules = sys.getattr("modules").map_err(|error| error.to_string())?;
    if modules.contains(script_name).map_err(|error| error.to_string())? {
        modules.del_item(script_name).map_err(|error| error.to_string())?;
    }
    Ok(())
}

pub(super) fn script_name_from_path(path: &Path) -> Result<String, String> {
    if path.extension().and_then(|extension| extension.to_str()) != Some("py") {
        return Err(format!("script path must end with .py: {}", path.display()));
    }
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("unable to derive script name from {}", path.display()))
}

fn load_script(py: Python<'_>, path: &Path, script_name: &str) -> PyResult<()> {
    let code = std::fs::read_to_string(path).map_err(|error| {
        PyRuntimeError::new_err(format!("failed to read {}: {error}", path.display()))
    })?;
    let code = CString::new(code).map_err(|_| {
        PyValueError::new_err(format!("script contains interior NUL: {}", path.display()))
    })?;
    let filename = CString::new(path.display().to_string())
        .map_err(|_| PyValueError::new_err(format!("invalid script path: {}", path.display())))?;
    let module_name = CString::new(script_name)
        .map_err(|_| PyValueError::new_err(format!("invalid script module name: {script_name}")))?;

    let module = PyModule::from_code(py, &code, &filename, &module_name)?;
    py.import("sys")?.getattr("modules")?.set_item(script_name, module)?;
    Ok(())
}
