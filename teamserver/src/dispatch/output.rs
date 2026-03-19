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
    use crate::{AgentRegistry, Database, EventBus, SocketRelayManager};

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

    // -- helpers for exit / kill-date callback tests --

    /// Build registry + event bus + socket relay manager with a pre-registered sample agent.
    async fn setup_with_sockets() -> (AgentRegistry, EventBus, SocketRelayManager) {
        let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
        let registry = AgentRegistry::new(db);
        let events = EventBus::new(16);
        registry.insert(sample_agent()).await.expect("insert sample agent");
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        (registry, events, sockets)
    }

    fn exit_payload(exit_method: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u32(&mut buf, exit_method);
        buf
    }

    // -- handle_exit_callback tests --

    #[tokio::test]
    async fn exit_callback_thread_exit_marks_agent_dead() {
        let (registry, events, sockets) = setup_with_sockets().await;
        let payload = exit_payload(1);

        let result = handle_exit_callback(
            &registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);

        let agent = registry.get(AGENT_ID).await.expect("agent must exist");
        assert!(!agent.active, "agent should be marked dead");
        assert!(
            agent.reason.contains("exit thread"),
            "reason should mention thread exit, got {:?}",
            agent.reason
        );
    }

    #[tokio::test]
    async fn exit_callback_process_exit_marks_agent_dead() {
        let (registry, events, sockets) = setup_with_sockets().await;
        let payload = exit_payload(2);

        handle_exit_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
            .await
            .expect("handler must succeed");

        let agent = registry.get(AGENT_ID).await.expect("agent must exist");
        assert!(!agent.active, "agent should be marked dead");
        assert!(
            agent.reason.contains("exit process"),
            "reason should mention process exit, got {:?}",
            agent.reason
        );
    }

    #[tokio::test]
    async fn exit_callback_unknown_method_marks_agent_dead_generic() {
        let (registry, events, sockets) = setup_with_sockets().await;
        let payload = exit_payload(99);

        handle_exit_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
            .await
            .expect("handler must succeed");

        let agent = registry.get(AGENT_ID).await.expect("agent must exist");
        assert!(!agent.active, "agent should be marked dead");
        assert_eq!(agent.reason, "Agent exited");
    }

    #[tokio::test]
    async fn exit_callback_broadcasts_mark_and_response() {
        let (registry, events, sockets) = setup_with_sockets().await;
        let mut rx = events.subscribe();
        let payload = exit_payload(1);

        handle_exit_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
            .await
            .expect("handler must succeed");

        // First broadcast: AgentUpdate (mark event)
        let msg1 = rx.recv().await.expect("should receive agent update");
        assert!(
            matches!(msg1, OperatorMessage::AgentUpdate(_)),
            "expected AgentUpdate, got {msg1:?}"
        );

        // Second broadcast: AgentResponse
        drop(events);
        let msg2 = rx.recv().await.expect("should receive agent response");
        let OperatorMessage::AgentResponse(resp) = &msg2 else {
            panic!("expected AgentResponse, got {msg2:?}");
        };
        let kind = resp.info.extra.get("Type").and_then(Value::as_str);
        assert_eq!(kind, Some("Good"));
        let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
        assert!(
            message.contains("exit thread"),
            "expected message about thread exit, got {message:?}"
        );
    }

    #[tokio::test]
    async fn exit_callback_empty_payload_returns_error() {
        let (registry, events, sockets) = setup_with_sockets().await;
        let payload = Vec::new();

        let result = handle_exit_callback(
            &registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload,
        )
        .await;
        let err = result.expect_err("empty payload must fail");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }

    // -- handle_kill_date_callback tests --

    #[tokio::test]
    async fn kill_date_callback_marks_agent_dead() {
        let (registry, events, sockets) = setup_with_sockets().await;
        let payload = Vec::new(); // kill date callback ignores payload

        handle_kill_date_callback(
            &registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload,
        )
        .await
        .expect("handler must succeed");

        let agent = registry.get(AGENT_ID).await.expect("agent must exist");
        assert!(!agent.active, "agent should be marked dead");
        assert!(
            agent.reason.contains("kill date"),
            "reason should mention kill date, got {:?}",
            agent.reason
        );
    }

    #[tokio::test]
    async fn kill_date_callback_broadcasts_mark_and_response() {
        let (registry, events, sockets) = setup_with_sockets().await;
        let mut rx = events.subscribe();
        let payload = Vec::new();

        handle_kill_date_callback(
            &registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload,
        )
        .await
        .expect("handler must succeed");

        // First broadcast: AgentUpdate (mark event)
        let msg1 = rx.recv().await.expect("should receive agent update");
        assert!(
            matches!(msg1, OperatorMessage::AgentUpdate(_)),
            "expected AgentUpdate, got {msg1:?}"
        );

        // Second broadcast: AgentResponse
        drop(events);
        let msg2 = rx.recv().await.expect("should receive agent response");
        let OperatorMessage::AgentResponse(resp) = &msg2 else {
            panic!("expected AgentResponse, got {msg2:?}");
        };
        let kind = resp.info.extra.get("Type").and_then(Value::as_str);
        assert_eq!(kind, Some("Good"));
        let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
        assert!(message.contains("kill date"), "expected message about kill date, got {message:?}");
    }

    // -- helpers for config callback tests --

    fn push_u64(buf: &mut Vec<u8>, value: u64) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Build a config callback payload: config key (u32) + extra fields.
    fn config_payload(key: u32, extra: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u32(&mut buf, key);
        buf.extend_from_slice(extra);
        buf
    }

    // -- KillDate tests --

    #[tokio::test]
    async fn config_kill_date_nonzero_sets_agent_kill_date() {
        let (registry, events) = setup().await;
        let kill_date_raw: u64 = 1_700_000_000;
        let mut extra = Vec::new();
        push_u64(&mut extra, kill_date_raw);
        let payload = config_payload(u32::from(DemonConfigKey::KillDate), &extra);

        let result =
            handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_ok());

        let agent = registry.get(AGENT_ID).await.expect("agent must exist");
        assert_eq!(agent.kill_date, Some(kill_date_raw as i64));
    }

    #[tokio::test]
    async fn config_kill_date_zero_disables_kill_date() {
        let (registry, events) = setup().await;

        // First set a non-zero kill date.
        let mut extra = Vec::new();
        push_u64(&mut extra, 1_700_000_000);
        let payload = config_payload(u32::from(DemonConfigKey::KillDate), &extra);
        handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload)
            .await
            .expect("set kill date must succeed");

        // Now disable it with raw=0.
        let mut extra_zero = Vec::new();
        push_u64(&mut extra_zero, 0);
        let payload_zero = config_payload(u32::from(DemonConfigKey::KillDate), &extra_zero);
        handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload_zero)
            .await
            .expect("disable kill date must succeed");

        let agent = registry.get(AGENT_ID).await.expect("agent must exist");
        assert_eq!(agent.kill_date, None, "kill_date should be None when raw=0");
    }

    #[tokio::test]
    async fn config_kill_date_broadcasts_mark_and_response() {
        let (registry, events) = setup().await;
        let mut rx = events.subscribe();

        let mut extra = Vec::new();
        push_u64(&mut extra, 1_700_000_000);
        let payload = config_payload(u32::from(DemonConfigKey::KillDate), &extra);

        handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload)
            .await
            .expect("handler must succeed");

        // First broadcast: AgentUpdate (mark event)
        let msg1 = rx.recv().await.expect("should receive agent update");
        assert!(
            matches!(msg1, OperatorMessage::AgentUpdate(_)),
            "expected AgentUpdate, got {msg1:?}"
        );

        // Second broadcast: AgentResponse
        drop(events);
        let msg2 = rx.recv().await.expect("should receive agent response");
        let OperatorMessage::AgentResponse(resp) = &msg2 else {
            panic!("expected AgentResponse, got {msg2:?}");
        };
        let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
        assert!(message.contains("KillDate"), "expected KillDate message, got {message:?}");
    }

    // -- WorkingHours tests --

    #[tokio::test]
    async fn config_working_hours_nonzero_sets_agent_working_hours() {
        let (registry, events) = setup().await;
        let raw: u32 = 0b101010;
        let mut extra = Vec::new();
        push_u32(&mut extra, raw);
        let payload = config_payload(u32::from(DemonConfigKey::WorkingHours), &extra);

        let result =
            handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(result.is_ok());

        let agent = registry.get(AGENT_ID).await.expect("agent must exist");
        assert_eq!(agent.working_hours, Some(42i32));
    }

    #[tokio::test]
    async fn config_working_hours_zero_disables_working_hours() {
        let (registry, events) = setup().await;

        // First set a non-zero value.
        let mut extra = Vec::new();
        push_u32(&mut extra, 0b101010);
        let payload = config_payload(u32::from(DemonConfigKey::WorkingHours), &extra);
        handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload)
            .await
            .expect("set working hours must succeed");

        // Now disable with raw=0.
        let mut extra_zero = Vec::new();
        push_u32(&mut extra_zero, 0);
        let payload_zero = config_payload(u32::from(DemonConfigKey::WorkingHours), &extra_zero);
        handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload_zero)
            .await
            .expect("disable working hours must succeed");

        let agent = registry.get(AGENT_ID).await.expect("agent must exist");
        assert_eq!(agent.working_hours, None, "working_hours should be None when raw=0");
    }

    #[tokio::test]
    async fn config_working_hours_broadcasts_mark_and_response() {
        let (registry, events) = setup().await;
        let mut rx = events.subscribe();

        let mut extra = Vec::new();
        push_u32(&mut extra, 0b101010);
        let payload = config_payload(u32::from(DemonConfigKey::WorkingHours), &extra);

        handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload)
            .await
            .expect("handler must succeed");

        let msg1 = rx.recv().await.expect("should receive agent update");
        assert!(
            matches!(msg1, OperatorMessage::AgentUpdate(_)),
            "expected AgentUpdate, got {msg1:?}"
        );

        drop(events);
        let msg2 = rx.recv().await.expect("should receive agent response");
        let OperatorMessage::AgentResponse(resp) = &msg2 else {
            panic!("expected AgentResponse, got {msg2:?}");
        };
        let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
        assert!(message.contains("WorkingHours"), "expected WorkingHours message, got {message:?}");
    }

    // -- Simple key (MemoryAlloc) test --

    #[tokio::test]
    async fn config_memory_alloc_formats_message_correctly() {
        let (registry, events) = setup().await;
        let mut rx = events.subscribe();

        let mut extra = Vec::new();
        push_u32(&mut extra, 42);
        let payload = config_payload(u32::from(DemonConfigKey::MemoryAlloc), &extra);

        handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload)
            .await
            .expect("handler must succeed");

        // MemoryAlloc only broadcasts a response, no AgentUpdate.
        let msg = rx.recv().await.expect("should receive agent response");
        let OperatorMessage::AgentResponse(resp) = &msg else {
            panic!("expected AgentResponse, got {msg:?}");
        };
        let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
        assert!(
            message.contains("42"),
            "expected message to contain the alloc value 42, got {message:?}"
        );
    }

    // -- Unknown config key test --

    #[tokio::test]
    async fn config_unknown_key_returns_error() {
        let (registry, events) = setup().await;
        let payload = config_payload(0xFFFF, &[]);

        let result =
            handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
        let err = result.expect_err("unknown config key must fail");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }

    // -- Truncated payload tests --

    #[tokio::test]
    async fn config_kill_date_truncated_payload_returns_error() {
        let (registry, events) = setup().await;
        // KillDate needs 8 bytes (u64) after the key, provide only 4.
        let mut extra = Vec::new();
        push_u32(&mut extra, 123);
        let payload = config_payload(u32::from(DemonConfigKey::KillDate), &extra);

        let result =
            handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
        let err = result.expect_err("truncated kill date payload must fail");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }

    #[tokio::test]
    async fn config_working_hours_truncated_payload_returns_error() {
        let (registry, events) = setup().await;
        // WorkingHours needs 4 bytes (u32) after the key, provide none.
        let payload = config_payload(u32::from(DemonConfigKey::WorkingHours), &[]);

        let result =
            handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
        let err = result.expect_err("truncated working hours payload must fail");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }

    #[tokio::test]
    async fn config_empty_payload_returns_error() {
        let (registry, events) = setup().await;
        let payload = Vec::new();

        let result =
            handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
        let err = result.expect_err("empty payload must fail");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }

    // -- handle_demon_info_callback tests ────────────────────────────────────

    fn demon_info_payload_mem_alloc(pointer: u64, size: u32, protection: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u32(&mut buf, u32::from(DemonInfoClass::MemAlloc));
        push_u64(&mut buf, pointer);
        push_u32(&mut buf, size);
        push_u32(&mut buf, protection);
        buf
    }

    fn demon_info_payload_mem_exec(function: u64, thread_id: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u32(&mut buf, u32::from(DemonInfoClass::MemExec));
        push_u64(&mut buf, function);
        push_u32(&mut buf, thread_id);
        buf
    }

    fn demon_info_payload_mem_protect(memory: u64, size: u32, old: u32, new: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u32(&mut buf, u32::from(DemonInfoClass::MemProtect));
        push_u64(&mut buf, memory);
        push_u32(&mut buf, size);
        push_u32(&mut buf, old);
        push_u32(&mut buf, new);
        buf
    }

    // -- handle_command_error_callback truncated payload tests --

    #[tokio::test]
    async fn command_error_win32_truncated_second_field_returns_error() {
        let (_registry, events) = setup().await;
        // Win32 error class present, but no subsequent error_code u32.
        let mut payload = Vec::new();
        push_u32(&mut payload, u32::from(DemonCallbackError::Win32));

        let result = handle_command_error_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        let err = result.expect_err("truncated Win32 payload must fail");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }

    #[tokio::test]
    async fn command_error_token_truncated_second_field_returns_error() {
        let (_registry, events) = setup().await;
        // Token error class present, but no subsequent status u32.
        let mut payload = Vec::new();
        push_u32(&mut payload, u32::from(DemonCallbackError::Token));

        let result = handle_command_error_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        let err = result.expect_err("truncated Token payload must fail");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }

    #[tokio::test]
    async fn command_error_truncated_before_error_class_returns_error() {
        let (_registry, events) = setup().await;
        // Only 2 bytes — not enough to read the error class u32.
        let payload = vec![0x01, 0x00];

        let result = handle_command_error_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        let err = result.expect_err("payload too short for error class must fail");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }

    // -- handle_demon_info_callback tests ────────────────────────────────────

    #[tokio::test]
    async fn demon_info_mem_alloc_formats_message() {
        let (_registry, events) = setup().await;
        let mut rx = events.subscribe();
        let payload = demon_info_payload_mem_alloc(0x7FFE_0000_1000, 4096, 0x04);

        let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert_eq!(result.expect("must succeed"), None);

        let msg = rx.recv().await.expect("should receive broadcast");
        let OperatorMessage::AgentResponse(resp) = &msg else {
            panic!("expected AgentResponse, got {msg:?}");
        };
        let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
        assert!(message.contains("0x7ffe00001000"), "expected pointer in message, got {message:?}");
        assert!(message.contains("4096"), "expected size in message, got {message:?}");
        assert!(
            message.contains("PAGE_READWRITE"),
            "expected protection name in message, got {message:?}"
        );
    }

    #[tokio::test]
    async fn demon_info_mem_exec_formats_message() {
        let (_registry, events) = setup().await;
        let mut rx = events.subscribe();
        let payload = demon_info_payload_mem_exec(0xDEAD_BEEF_CAFE, 42);

        let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert_eq!(result.expect("must succeed"), None);

        let msg = rx.recv().await.expect("should receive broadcast");
        let OperatorMessage::AgentResponse(resp) = &msg else {
            panic!("expected AgentResponse, got {msg:?}");
        };
        let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
        assert!(
            message.contains("0xdeadbeefcafe"),
            "expected function pointer in message, got {message:?}"
        );
        assert!(message.contains("42"), "expected thread id in message, got {message:?}");
    }

    #[tokio::test]
    async fn demon_info_mem_protect_formats_both_protections() {
        let (_registry, events) = setup().await;
        let mut rx = events.subscribe();
        let payload = demon_info_payload_mem_protect(0x1000_2000, 8192, 0x02, 0x40);

        let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert_eq!(result.expect("must succeed"), None);

        let msg = rx.recv().await.expect("should receive broadcast");
        let OperatorMessage::AgentResponse(resp) = &msg else {
            panic!("expected AgentResponse, got {msg:?}");
        };
        let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
        assert!(
            message.contains("0x10002000"),
            "expected memory address in message, got {message:?}"
        );
        assert!(message.contains("8192"), "expected size in message, got {message:?}");
        assert!(
            message.contains("PAGE_READONLY"),
            "expected old protection in message, got {message:?}"
        );
        assert!(
            message.contains("PAGE_EXECUTE_READWRITE"),
            "expected new protection in message, got {message:?}"
        );
    }

    #[tokio::test]
    async fn demon_info_unknown_class_returns_ok_none() {
        let (_registry, events) = setup().await;
        // Use a class value that doesn't map to any DemonInfoClass variant.
        let mut payload = Vec::new();
        push_u32(&mut payload, 0xFF);

        let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert_eq!(result.expect("unknown class must not error"), None);
    }

    #[tokio::test]
    async fn demon_info_mem_alloc_truncated_returns_error() {
        let (_registry, events) = setup().await;
        // Only info class, missing pointer/size/protection.
        let mut payload = Vec::new();
        push_u32(&mut payload, u32::from(DemonInfoClass::MemAlloc));

        let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        let err = result.expect_err("truncated MemAlloc payload must fail");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }

    #[tokio::test]
    async fn demon_info_mem_exec_truncated_returns_error() {
        let (_registry, events) = setup().await;
        // Only info class, missing function/thread_id.
        let mut payload = Vec::new();
        push_u32(&mut payload, u32::from(DemonInfoClass::MemExec));

        let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        let err = result.expect_err("truncated MemExec payload must fail");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }

    #[tokio::test]
    async fn demon_info_mem_protect_truncated_returns_error() {
        let (_registry, events) = setup().await;
        // Only info class + memory address, missing size/old/new.
        let mut payload = Vec::new();
        push_u32(&mut payload, u32::from(DemonInfoClass::MemProtect));
        push_u64(&mut payload, 0x1000);

        let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        let err = result.expect_err("truncated MemProtect payload must fail");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }
}
