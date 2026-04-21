//! Command registration parsing, callback invocation, and `#[pyfunction]` registration endpoints.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};

use super::helpers::ensure_callable;
use super::types::{PyAgent, PyCommandContext};
use super::{CommandOption, CommandOptionType};
use super::{PythonApiState, ScriptOutputStream, active_api_state};

pub(super) struct RegisterCommandRequest {
    pub(super) name: String,
    pub(super) description: Option<String>,
    pub(super) options: Vec<CommandOption>,
    pub(super) callback: Py<PyAny>,
}

#[derive(Clone, Copy)]
pub(super) enum PyCallShape {
    AgentArgsContext,
    AgentArgs,
    ContextOnly,
    AgentOnly,
    NoArgs,
}

pub(super) fn write_callback_result(
    api_state: &PythonApiState,
    script_name: &str,
    value: &Bound<'_, PyAny>,
) -> Result<(), String> {
    if value.is_none() {
        return Ok(());
    }

    let mut rendered = value
        .str()
        .and_then(|text| text.to_str().map(str::to_owned))
        .map_err(|error| error.to_string())?;
    if rendered.trim().is_empty() {
        return Ok(());
    }
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    let _ = api_state.push_output(Some(script_name), ScriptOutputStream::Stdout, &rendered);
    Ok(())
}

pub(super) fn invoke_registered_command_callback(
    api_state: &PythonApiState,
    py: Python<'_>,
    script_name: &str,
    callback: &Bound<'_, PyAny>,
    agent: Py<PyAgent>,
    context: Py<PyCommandContext>,
    arguments: &[String],
) -> Result<bool, String> {
    let attempts = [
        PyCallShape::AgentArgsContext,
        PyCallShape::AgentArgs,
        PyCallShape::ContextOnly,
        PyCallShape::AgentOnly,
        PyCallShape::NoArgs,
    ];

    for shape in attempts {
        if !callback_accepts_shape(py, callback, shape)? {
            continue;
        }
        let result = match shape {
            PyCallShape::AgentArgsContext => {
                callback.call1((agent.clone_ref(py), arguments.to_vec(), context.clone_ref(py)))
            }
            PyCallShape::AgentArgs => callback.call1((agent.clone_ref(py), arguments.to_vec())),
            PyCallShape::ContextOnly => callback.call1((context.clone_ref(py),)),
            PyCallShape::AgentOnly => callback.call1((agent.clone_ref(py),)),
            PyCallShape::NoArgs => callback.call0(),
        };
        let value = result.map_err(|error| error.to_string())?;
        write_callback_result(api_state, script_name, &value)?;
        return Ok(true);
    }

    let _ = agent;
    Err("registered command callback does not accept any supported signature".to_owned())
}

fn callback_accepts_shape(
    py: Python<'_>,
    callback: &Bound<'_, PyAny>,
    shape: PyCallShape,
) -> Result<bool, String> {
    let inspect = py.import("inspect").map_err(|error| error.to_string())?;
    let signature = match inspect.call_method1("signature", (callback,)) {
        Ok(signature) => signature,
        Err(_) => return Ok(true),
    };

    let args = match shape {
        PyCallShape::AgentArgsContext => 3_usize,
        PyCallShape::AgentArgs => 2,
        PyCallShape::ContextOnly | PyCallShape::AgentOnly => 1,
        PyCallShape::NoArgs => 0,
    };
    let probe =
        PyTuple::new(py, (0..args).map(|_| py.None())).map_err(|error| error.to_string())?;
    Ok(signature.call_method1("bind_partial", probe).is_ok())
}

fn optional_kwarg<'py>(
    kwargs: Option<&Bound<'py, PyDict>>,
    key: &str,
) -> PyResult<Option<Bound<'py, PyAny>>> {
    match kwargs {
        Some(kwargs) => kwargs.get_item(key),
        None => Ok(None),
    }
}

fn extract_string_argument(
    kwargs: Option<&Bound<'_, PyDict>>,
    key: &str,
    positional: Option<&Bound<'_, PyAny>>,
) -> PyResult<Option<String>> {
    if let Some(value) = optional_kwarg(kwargs, key)? {
        return value.extract::<String>().map(Some);
    }
    positional.map(Bound::extract::<String>).transpose()
}

/// Parse a Python value (list of dicts) into a `Vec<CommandOption>`.
fn parse_options(value: &Bound<'_, PyAny>) -> PyResult<Vec<CommandOption>> {
    if value.is_none() {
        return Ok(Vec::new());
    }
    let list = value.try_iter().map_err(|_| {
        PyValueError::new_err(
            "options must be a list of dicts with 'name', 'type', 'required', 'default'",
        )
    })?;
    let mut options = Vec::new();
    for item in list {
        let item = item?;
        let dict = item.downcast::<PyDict>().map_err(|_| {
            PyValueError::new_err(
                "each option must be a dict with 'name', 'type', 'required', 'default'",
            )
        })?;
        let name = dict
            .get_item("name")?
            .ok_or_else(|| PyValueError::new_err("option is missing 'name'"))?
            .extract::<String>()?;
        let type_str = match dict.get_item("type")? {
            Some(v) => v.extract::<String>()?,
            None => "string".to_owned(),
        };
        let option_type = CommandOptionType::from_str(&type_str)?;
        let required = match dict.get_item("required")? {
            Some(v) => v.extract::<bool>()?,
            None => false,
        };
        let default = match dict.get_item("default")? {
            Some(v) if !v.is_none() => Some(v.extract::<String>()?),
            _ => None,
        };
        options.push(CommandOption { name, option_type, required, default });
    }
    Ok(options)
}

fn parse_register_command_request(
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<RegisterCommandRequest> {
    let positional = args.iter().collect::<Vec<_>>();
    let havoc_style = optional_kwarg(kwargs, "function")?.is_some()
        || positional.first().is_some_and(Bound::is_callable);

    if havoc_style {
        let callback = if let Some(value) = optional_kwarg(kwargs, "function")? {
            value
        } else {
            positional
                .first()
                .cloned()
                .ok_or_else(|| PyValueError::new_err("RegisterCommand requires a callable"))?
        };
        ensure_callable(&callback)?;
        let module = extract_string_argument(kwargs, "module", positional.get(1))?
            .ok_or_else(|| PyValueError::new_err("RegisterCommand requires a module name"))?;
        let command = extract_string_argument(kwargs, "command", positional.get(2))?
            .ok_or_else(|| PyValueError::new_err("RegisterCommand requires a command name"))?;
        let description = extract_string_argument(kwargs, "description", positional.get(3))?;
        let options = optional_kwarg(kwargs, "options")?
            .as_ref()
            .map(parse_options)
            .transpose()?
            .unwrap_or_default();
        let name = if module.trim().is_empty() { command } else { format!("{module} {command}") };
        return Ok(RegisterCommandRequest {
            name,
            description,
            options,
            callback: callback.unbind(),
        });
    }

    let callback = if let Some(value) = optional_kwarg(kwargs, "callback")? {
        value
    } else {
        positional
            .get(1)
            .cloned()
            .ok_or_else(|| PyValueError::new_err("register_command requires a callback"))?
    };
    ensure_callable(&callback)?;
    let name = extract_string_argument(kwargs, "name", positional.first())?
        .ok_or_else(|| PyValueError::new_err("register_command requires a command name"))?;
    let description = extract_string_argument(kwargs, "description", positional.get(2))?;
    let options = if let Some(value) = optional_kwarg(kwargs, "options")? {
        parse_options(&value)?
    } else {
        positional.get(3).map(parse_options).transpose()?.unwrap_or_default()
    };
    Ok(RegisterCommandRequest { name, description, options, callback: callback.unbind() })
}

#[pyfunction]
#[pyo3(signature = (*args, **kwargs))]
pub(super) fn register_command(
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<()> {
    let request = parse_register_command_request(args, kwargs)?;
    let api_state = active_api_state()?;
    api_state.register_command(request.name, request.description, request.options, request.callback)
}

/// Parse a `havocui.RegisterCommand` call.
///
/// Supported forms:
/// - `(name, callback)` — 2-arg backward-compatible
/// - `(name, description, options, callback)` — full 4-arg form
/// - keyword arguments: `name=`, `description=`, `options=`, `callback=`
fn parse_havocui_register_command_request(
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<RegisterCommandRequest> {
    let positional = args.iter().collect::<Vec<_>>();

    // Prefer explicit keyword form for any argument.
    let callback = if let Some(value) = optional_kwarg(kwargs, "callback")? {
        value
    } else if let Some(cb) = positional.last().filter(|v| v.is_callable()) {
        cb.clone()
    } else {
        return Err(PyValueError::new_err(
            "havocui.RegisterCommand requires a callable as the last positional argument or `callback=`",
        ));
    };
    ensure_callable(&callback)?;

    let name = extract_string_argument(kwargs, "name", positional.first())?
        .ok_or_else(|| PyValueError::new_err("havocui.RegisterCommand requires a command name"))?;

    // 2-arg form: (name, callback) — no description or options.
    // 4-arg form: (name, description, options, callback).
    let (description, options) = if positional.len() == 4 {
        let desc = extract_string_argument(kwargs, "description", positional.get(1))?;
        let opts = match positional.get(2) {
            Some(v) => parse_options(v)?,
            None => Vec::new(),
        };
        (desc, opts)
    } else {
        let desc = extract_string_argument(kwargs, "description", None)?;
        let opts = optional_kwarg(kwargs, "options")?
            .as_ref()
            .map(parse_options)
            .transpose()?
            .unwrap_or_default();
        (desc, opts)
    };

    Ok(RegisterCommandRequest { name, description, options, callback: callback.unbind() })
}

/// Register a command via the `havocui` module.
///
/// Supported forms:
/// - `havocui.RegisterCommand(name, callback)` — backward-compatible 2-arg form
/// - `havocui.RegisterCommand(name, description, options, callback)` — full form
/// - keyword arguments: `name=`, `description=`, `options=`, `callback=`
#[pyfunction]
#[pyo3(name = "register_command")]
#[pyo3(signature = (*args, **kwargs))]
pub(super) fn havocui_register_command(
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<()> {
    let request = parse_havocui_register_command_request(args, kwargs)?;
    let api_state = active_api_state()?;
    api_state.register_command(request.name, request.description, request.options, request.callback)
}
