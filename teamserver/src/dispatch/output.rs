use std::collections::BTreeMap;

use red_cell_common::demon::{
    DemonCallbackError, DemonCommand, DemonConfigKey, DemonInfoClass, DemonJobCommand,
};
use tracing::warn;

use crate::agent_events::agent_mark_event;
use crate::events::broadcast_teamserver_warning;
use crate::{
    AgentRegistry, Database, EventBus, PluginRuntime, SocketRelayManager, TeamserverError,
};

use super::checkin::decode_working_hours;
use super::process::{format_memory_protect, win32_error_code_name};
use super::{
    AgentResponseEntry, CallbackParser, CommandDispatchError, agent_response_event, bool_string,
    broadcast_and_persist_agent_response, job_state_name, job_type_name, loot_context,
    parse_optional_kill_date, persist_credentials_from_output,
};

pub(super) async fn handle_command_output_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandOutput));
    let output = parser.read_string("command output text")?;
    // The Red Cell Specter agent appends a trailing i32 (LE) exit code after
    // the length-prefixed output string.  Original Havoc demons do not send
    // this field, so we read it only when bytes remain in the payload.
    let mut extra = BTreeMap::new();
    if !parser.is_empty() {
        if let Ok(raw) = parser.read_u32("command exit code") {
            #[allow(clippy::cast_possible_wrap)]
            extra.insert("ExitCode".to_owned(), serde_json::Value::Number((raw as i32).into()));
        }
    }
    let context = loot_context(registry, agent_id, request_id).await;
    // Empty body is normal for some tasks (`kill`, etc.).  `broadcast_and_persist_agent_response`
    // synthesizes a TaskID from `request_id` when queue metadata is missing so REST
    // `exec --wait` and output polling still see a terminal row (red-cell-c2-1f7q1).
    broadcast_and_persist_agent_response(
        database,
        events,
        AgentResponseEntry {
            agent_id,
            command_id: u32::from(DemonCommand::CommandOutput),
            request_id,
            kind: "Good".to_owned(),
            message: format!("Received Output [{} bytes]:", output.len()),
            extra,
            output: output.clone(),
        },
        &context,
    )
    .await?;
    persist_credentials_from_output(
        database,
        events,
        plugins,
        agent_id,
        u32::from(DemonCommand::CommandOutput),
        request_id,
        &output,
        &context,
    )
    .await?;
    if let Some(plugins) = plugins
        && let Err(error) = plugins
            .emit_command_output(
                agent_id,
                u32::from(DemonCommand::CommandOutput),
                request_id,
                &output,
            )
            .await
    {
        warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python command_output event");
    }
    Ok(None)
}

pub(super) async fn handle_command_error_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandError));
    let error_class = parser.read_u32("command error class")?;

    let message = match DemonCallbackError::try_from(error_class) {
        Ok(DemonCallbackError::Win32) => {
            let error_code = parser.read_u32("command error win32 code")?;
            match win32_error_code_name(error_code) {
                Some(name) => format!("Win32 Error: {name} [{error_code}]"),
                None => format!("Win32 Error: [{error_code}]"),
            }
        }
        Ok(DemonCallbackError::Token) => {
            let status = parser.read_u32("command error token status")?;
            match status {
                0x1 => "No tokens inside the token vault".to_owned(),
                other => format!("Token operation failed with status 0x{other:X}"),
            }
        }
        Ok(DemonCallbackError::Coffee) => {
            return Ok(None);
        }
        Ok(DemonCallbackError::Generic) => {
            let text = parser.read_string("command error message")?;
            let context = loot_context(registry, agent_id, request_id).await;
            broadcast_and_persist_agent_response(
                database,
                events,
                AgentResponseEntry {
                    agent_id,
                    command_id: u32::from(DemonCommand::CommandError),
                    request_id,
                    kind: "Error".to_owned(),
                    message: "Agent Error".to_owned(),
                    extra: BTreeMap::new(),
                    output: text,
                },
                &context,
            )
            .await?;
            return Ok(None);
        }
        Err(unknown) => {
            broadcast_teamserver_warning(
                events,
                format!(
                    "[callback CommandError] agent {agent_id:08X} request 0x{request_id:X} unknown error class ({unknown}) — dropped"
                ),
            );
            return Ok(None);
        }
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandError),
        request_id,
        "Error",
        &message,
        None,
    )?);
    Ok(None)
}

pub(super) async fn handle_exit_callback(
    registry: &AgentRegistry,
    sockets: &SocketRelayManager,
    events: &EventBus,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandExit));
    let exit_method = parser.read_u32("command exit method")?;
    let message = match exit_method {
        1 => "Agent has been tasked to cleanup and exit thread. cya...",
        2 => "Agent has been tasked to cleanup and exit process. cya...",
        _ => "Agent exited",
    };

    mark_agent_dead_and_broadcast(
        registry,
        sockets,
        events,
        plugins,
        agent_id,
        u32::from(DemonCommand::CommandExit),
        request_id,
        message,
    )
    .await
}

pub(super) async fn handle_kill_date_callback(
    registry: &AgentRegistry,
    sockets: &SocketRelayManager,
    events: &EventBus,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    request_id: u32,
    _payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    mark_agent_dead_and_broadcast(
        registry,
        sockets,
        events,
        plugins,
        agent_id,
        u32::from(DemonCommand::CommandKillDate),
        request_id,
        "Agent has reached its kill date, tasked to cleanup and exit thread. cya...",
    )
    .await
}

pub(super) async fn mark_agent_dead_and_broadcast(
    registry: &AgentRegistry,
    sockets: &SocketRelayManager,
    events: &EventBus,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    message: &str,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    registry.mark_dead(agent_id, message).await?;
    sockets.remove_agent(agent_id).await;
    if let Some(agent) = registry.get(agent_id).await {
        events.broadcast(agent_mark_event(&agent));
    }
    events
        .broadcast(agent_response_event(agent_id, command_id, request_id, "Good", message, None)?);
    if let Some(plugins) = plugins
        && let Err(error) = plugins.emit_agent_dead(agent_id).await
    {
        warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python agent_dead event");
    }
    Ok(None)
}

pub(super) async fn handle_demon_info_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::DemonInfo));
    let info_class = parser.read_u32("demon info class")?;

    let message = match DemonInfoClass::try_from(info_class) {
        Ok(DemonInfoClass::MemAlloc) => {
            let pointer = parser.read_u64("demon info mem alloc pointer")?;
            let size = parser.read_u32("demon info mem alloc size")?;
            let protection = parser.read_u32("demon info mem alloc protection")?;
            format!(
                "Memory Allocated : Pointer:[0x{pointer:x}] Size:[{size}] Protection:[{}]",
                format_memory_protect(protection)
            )
        }
        Ok(DemonInfoClass::MemExec) => {
            let function = parser.read_u64("demon info mem exec function")?;
            let thread_id = parser.read_u32("demon info mem exec thread id")?;
            format!("Memory Executed  : Function:[0x{function:x}] ThreadId:[{thread_id}]")
        }
        Ok(DemonInfoClass::MemProtect) => {
            let memory = parser.read_u64("demon info mem protect memory")?;
            let size = parser.read_u32("demon info mem protect size")?;
            let old = parser.read_u32("demon info mem protect old protection")?;
            let new = parser.read_u32("demon info mem protect protection")?;
            format!(
                "Memory Protection: Memory:[0x{memory:x}] Size:[{size}] Protection[{} -> {}]",
                format_memory_protect(old),
                format_memory_protect(new)
            )
        }
        Ok(DemonInfoClass::ProcCreate) => {
            let path = parser.read_utf16("demon info proc create path")?;
            let pid = parser.read_u32("demon info proc create pid")?;
            let success = parser.read_bool("demon info proc create success")?;
            let piped = parser.read_bool("demon info proc create piped")?;
            let verbose = parser.read_bool("demon info proc create verbose")?;

            if !verbose {
                return Ok(None);
            }

            if success {
                format!("Process started: Path:[{path}] ProcessID:[{pid}]")
            } else if !piped {
                format!("Process could not be started: Path:[{path}]")
            } else {
                format!("Process started without output pipe: Path:[{path}] ProcessID:[{pid}]")
            }
        }
        Err(unknown) => {
            broadcast_teamserver_warning(
                events,
                format!(
                    "[callback DemonInfo] agent {agent_id:08X} request 0x{request_id:X} unknown info class ({unknown}) — dropped"
                ),
            );
            return Ok(None);
        }
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::DemonInfo),
        request_id,
        "Info",
        &message,
        None,
    )?);
    Ok(None)
}

pub(super) async fn handle_job_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandJob));
    let subcommand = parser.read_u32("job subcommand")?;
    let subcommand = DemonJobCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandJob),
            message: error.to_string(),
        }
    })?;

    match subcommand {
        DemonJobCommand::List => {
            let mut rows = Vec::new();
            while !parser.is_empty() {
                rows.push((
                    parser.read_u32("job list id")?,
                    parser.read_u32("job list type")?,
                    parser.read_u32("job list state")?,
                ));
            }

            let mut output =
                String::from(" Job ID  Type           State\n ------  ----           -----\n");
            for (job_id, job_type, state) in rows {
                output.push_str(&format!(
                    " {job_id:<6}  {:<13}  {}\n",
                    job_type_name(job_type),
                    job_state_name(state)
                ));
            }
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandJob),
                request_id,
                "Info",
                "Job list:",
                Some(output.trim_end().to_owned()),
            )?);
        }
        DemonJobCommand::Suspend | DemonJobCommand::Resume | DemonJobCommand::KillRemove => {
            let job_id = parser.read_u32("job action id")?;
            let success = parser.read_bool("job action success")?;
            let (success_text, failure_text) = match subcommand {
                DemonJobCommand::Suspend => ("Successfully suspended job", "Failed to suspend job"),
                DemonJobCommand::Resume => ("Successfully resumed job", "Failed to resume job"),
                DemonJobCommand::KillRemove => {
                    ("Successfully killed and removed job", "Failed to kill job")
                }
                DemonJobCommand::List | DemonJobCommand::Died => unreachable!(),
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandJob),
                request_id,
                if success { "Good" } else { "Error" },
                &format!("{} {job_id}", if success { success_text } else { failure_text }),
                None,
            )?);
        }
        DemonJobCommand::Died => {}
    }

    Ok(None)
}

pub(super) async fn handle_sleep_callback(
    registry: &AgentRegistry,
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandSleep));
    let sleep_delay = parser.read_u32("sleep delay")?;
    let sleep_jitter = parser.read_u32("sleep jitter")?;
    let mut agent =
        registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
    agent.sleep_delay = sleep_delay;
    agent.sleep_jitter = sleep_jitter;
    registry.update_agent(agent.clone()).await?;
    events.broadcast(agent_mark_event(&agent));
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandSleep),
        request_id,
        "Good",
        &format!("Set sleep interval to {sleep_delay} seconds with {sleep_jitter}% jitter"),
        None,
    )?);
    Ok(None)
}

pub(super) async fn handle_config_callback(
    registry: &AgentRegistry,
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandConfig));
    let key = parser.read_u32("config key")?;
    let key = DemonConfigKey::try_from(key).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandConfig),
            message: error.to_string(),
        }
    })?;

    let message = match key {
        DemonConfigKey::MemoryAlloc => {
            format!("Default memory allocation set to {}", parser.read_u32("config value")?)
        }
        DemonConfigKey::MemoryExecute => {
            format!("Default memory executing set to {}", parser.read_u32("config value")?)
        }
        DemonConfigKey::InjectSpawn64 => {
            format!("Default x64 target process set to {}", parser.read_utf16("config path")?)
        }
        DemonConfigKey::InjectSpawn32 => {
            format!("Default x86 target process set to {}", parser.read_utf16("config path")?)
        }
        DemonConfigKey::KillDate => {
            let raw = parser.read_u64("config kill date")?;
            let mut agent =
                registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
            agent.kill_date = parse_optional_kill_date(
                raw,
                u32::from(DemonCommand::CommandConfig),
                "config kill date",
            )?;
            registry.update_agent(agent.clone()).await?;
            events.broadcast(agent_mark_event(&agent));
            if raw == 0 {
                "KillDate was disabled".to_owned()
            } else {
                "KillDate has been set".to_owned()
            }
        }
        DemonConfigKey::WorkingHours => {
            let raw = parser.read_u32("config working hours")?;
            let mut agent =
                registry.get(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
            agent.working_hours = decode_working_hours(raw);
            registry.update_agent(agent.clone()).await?;
            events.broadcast(agent_mark_event(&agent));
            if raw == 0 {
                "WorkingHours was disabled".to_owned()
            } else {
                "WorkingHours has been set".to_owned()
            }
        }
        DemonConfigKey::ImplantSpfThreadStart => {
            let module = parser.read_string("config spf module")?;
            let symbol = parser.read_string("config spf symbol")?;
            format!("Sleep obfuscation spoof thread start addr to {module}!{symbol}")
        }
        DemonConfigKey::ImplantSleepTechnique => {
            format!("Sleep obfuscation technique set to {}", parser.read_u32("config value")?)
        }
        DemonConfigKey::ImplantCoffeeVeh => {
            format!("Coffee VEH set to {}", bool_string(parser.read_bool("config coffee veh")?))
        }
        DemonConfigKey::ImplantCoffeeThreaded => format!(
            "Coffee threading set to {}",
            bool_string(parser.read_bool("config coffee threaded")?)
        ),
        DemonConfigKey::InjectTechnique => {
            format!("Set default injection technique to {}", parser.read_u32("config value")?)
        }
        DemonConfigKey::InjectSpoofAddr => {
            let module = parser.read_string("config inject spoof module")?;
            let symbol = parser.read_string("config inject spoof symbol")?;
            format!("Injection thread spoofing value set to {module}!{symbol}")
        }
        DemonConfigKey::ImplantVerbose => format!(
            "Implant verbose messaging: {}",
            bool_string(parser.read_bool("config implant verbose")?)
        ),
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandConfig),
        request_id,
        "Good",
        &message,
        None,
    )?);
    Ok(None)
}
