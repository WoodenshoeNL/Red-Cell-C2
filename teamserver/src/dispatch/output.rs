use std::collections::BTreeMap;

use red_cell_common::demon::{
    DemonCallbackError, DemonCommand, DemonConfigKey, DemonInfoClass, DemonJobCommand,
};
use tracing::warn;

use crate::agent_events::agent_mark_event;
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
    if output.is_empty() {
        return Ok(None);
    }
    let context = loot_context(registry, agent_id, request_id).await;
    broadcast_and_persist_agent_response(
        database,
        events,
        AgentResponseEntry {
            agent_id,
            command_id: u32::from(DemonCommand::CommandOutput),
            request_id,
            kind: "Good".to_owned(),
            message: format!("Received Output [{} bytes]:", output.len()),
            extra: BTreeMap::new(),
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
        Err(_) => return Ok(None),
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
        Err(_) => return Ok(None),
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

#[cfg(test)]
mod tests {
    use red_cell_common::operator::OperatorMessage;
    use serde_json::Value;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{AgentRegistry, Database, EventBus};

    const AGENT_ID: u32 = 0xBEEF_0001;
    const REQUEST_ID: u32 = 99;

    fn push_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn sample_agent() -> red_cell_common::AgentRecord {
        red_cell_common::AgentRecord {
            agent_id: AGENT_ID,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: red_cell_common::AgentEncryptionInfo {
                aes_key: Zeroizing::new(vec![0u8; 32]),
                aes_iv: Zeroizing::new(vec![0u8; 16]),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "lab".to_owned(),
            external_ip: "127.0.0.1".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_path: "C:\\Windows\\explorer.exe".to_owned(),
            base_address: 0x1000,
            process_pid: 1337,
            process_tid: 7331,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_build: 0,
            os_arch: "x64".to_owned(),
            sleep_delay: 10,
            sleep_jitter: 25,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-03-09T20:00:00Z".to_owned(),
            last_call_in: "2026-03-09T20:00:00Z".to_owned(),
        }
    }

    /// Build registry + event bus with a pre-registered sample agent.
    async fn setup() -> (AgentRegistry, EventBus) {
        let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
        let registry = AgentRegistry::new(db);
        let events = EventBus::new(16);
        registry.insert(sample_agent()).await.expect("insert sample agent");
        (registry, events)
    }

    fn sleep_payload(delay: u32, jitter: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u32(&mut buf, delay);
        push_u32(&mut buf, jitter);
        buf
    }

    #[tokio::test]
    async fn sleep_callback_updates_agent_state() {
        let (registry, events) = setup().await;
        let payload = sleep_payload(60, 20);

        let result =
            handle_sleep_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);

        let agent = registry.get(AGENT_ID).await.expect("agent must exist");
        assert_eq!(agent.sleep_delay, 60);
        assert_eq!(agent.sleep_jitter, 20);
    }

    #[tokio::test]
    async fn sleep_callback_broadcasts_agent_update_and_response() {
        let (registry, events) = setup().await;
        let mut rx = events.subscribe();
        let payload = sleep_payload(30, 10);

        handle_sleep_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload)
            .await
            .expect("handler must succeed");

        // First broadcast: AgentUpdate (mark event)
        let msg1 = rx.recv().await.expect("should receive agent update");
        assert!(
            matches!(msg1, OperatorMessage::AgentUpdate(_)),
            "expected AgentUpdate, got {msg1:?}"
        );

        // Second broadcast: AgentResponse
        // Drop the event bus so recv returns None after the last queued message.
        drop(events);
        let msg2 = rx.recv().await.expect("should receive agent response");
        let OperatorMessage::AgentResponse(resp) = &msg2 else {
            panic!("expected AgentResponse, got {msg2:?}");
        };
        assert_eq!(resp.info.demon_id, format!("{AGENT_ID:08X}"));
        let kind = resp.info.extra.get("Type").and_then(Value::as_str);
        assert_eq!(kind, Some("Good"));
        let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
        assert!(
            message.contains("30") && message.contains("10"),
            "expected message to contain delay=30 and jitter=10, got {message:?}"
        );
    }

    #[tokio::test]
    async fn sleep_callback_truncated_payload_returns_error() {
        let (registry, events) = setup().await;
        // Only 4 bytes — missing the jitter field.
        let mut payload = Vec::new();
        push_u32(&mut payload, 60);

        let result =
            handle_sleep_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
        let err = result.expect_err("truncated payload must fail");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }

    #[tokio::test]
    async fn sleep_callback_empty_payload_returns_error() {
        let (registry, events) = setup().await;
        let payload = Vec::new();

        let result =
            handle_sleep_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
        let err = result.expect_err("empty payload must fail");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }

    #[tokio::test]
    async fn sleep_callback_agent_not_found_returns_error() {
        let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
        let registry = AgentRegistry::new(db);
        let events = EventBus::new(8);
        let payload = sleep_payload(60, 20);
        let nonexistent_id = 0xDEAD_FFFF;

        let result =
            handle_sleep_callback(&registry, &events, nonexistent_id, REQUEST_ID, &payload).await;
        let err = result.expect_err("nonexistent agent must fail");
        assert!(
            matches!(err, CommandDispatchError::Registry(TeamserverError::AgentNotFound { .. })),
            "expected AgentNotFound, got {err:?}"
        );
    }
}
