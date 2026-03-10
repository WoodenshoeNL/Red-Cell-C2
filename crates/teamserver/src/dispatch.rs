//! Command routing for parsed Demon callback packages.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, encrypt_agent_data};
use red_cell_common::demon::{
    DemonCommand, DemonInjectError, DemonMessage, DemonPackage, DemonProcessCommand,
    DemonProtocolError, DemonTokenCommand,
};
use red_cell_common::operator::{
    AgentResponseInfo, AgentUpdateInfo, EventCode, Message, MessageHead, OperatorMessage,
};
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{AgentRegistry, DemonCallbackPackage, EventBus, TeamserverError};

type HandlerFuture =
    Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, CommandDispatchError>> + Send>>;
type Handler = dyn Fn(u32, u32, Vec<u8>) -> HandlerFuture + Send + Sync + 'static;

/// Error returned while routing or executing a Demon command handler.
#[derive(Debug, Error)]
pub enum CommandDispatchError {
    /// The dispatcher could not update shared teamserver state.
    #[error("{0}")]
    Registry(#[from] TeamserverError),
    /// A handler failed to serialize its response in Havoc's package format.
    #[error("failed to serialize demon response: {0}")]
    Protocol(#[from] DemonProtocolError),
    /// The dispatcher could not format a callback timestamp.
    #[error("failed to format callback timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
    /// Stored AES material is invalid.
    #[error("invalid base64 in stored {field} for agent 0x{agent_id:08X}: {message}")]
    InvalidStoredCryptoEncoding {
        /// Agent identifier associated with the invalid value.
        agent_id: u32,
        /// Stored field name.
        field: &'static str,
        /// Decoder error message.
        message: String,
    },
    /// Stored AES material decoded to an unexpected length.
    #[error("stored {field} for agent 0x{agent_id:08X} has {actual} bytes, expected {expected}")]
    InvalidStoredCryptoLength {
        /// Agent identifier associated with the invalid value.
        agent_id: u32,
        /// Stored field name.
        field: &'static str,
        /// Required decoded length.
        expected: usize,
        /// Observed decoded length.
        actual: usize,
    },
    /// A callback payload could not be parsed according to the Havoc wire format.
    #[error("failed to parse callback payload for command 0x{command_id:08X}: {message}")]
    InvalidCallbackPayload {
        /// Raw command identifier associated with the callback.
        command_id: u32,
        /// Human-readable parser error.
        message: String,
    },
}

/// Central registry of Demon command handlers keyed by command identifier.
#[derive(Clone)]
pub struct CommandDispatcher {
    handlers: Arc<HashMap<u32, Arc<Handler>>>,
}

impl std::fmt::Debug for CommandDispatcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut commands = self.handlers.keys().copied().collect::<Vec<_>>();
        commands.sort_unstable();
        formatter.debug_struct("CommandDispatcher").field("registered_commands", &commands).finish()
    }
}

impl Default for CommandDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandDispatcher {
    /// Create an empty dispatcher with no registered handlers.
    #[must_use]
    pub fn new() -> Self {
        Self { handlers: Arc::new(HashMap::new()) }
    }

    /// Create a dispatcher with the built-in `COMMAND_GET_JOB` and `COMMAND_CHECKIN` handlers.
    #[must_use]
    pub fn with_builtin_handlers(registry: AgentRegistry, events: EventBus) -> Self {
        let mut dispatcher = Self::new();

        let get_job_registry = registry.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandGetJob),
            move |agent_id, _, _| {
                let registry = get_job_registry.clone();
                Box::pin(async move { handle_get_job(&registry, agent_id).await })
            },
        );

        let checkin_events = events.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandCheckin),
            move |agent_id, _, _| {
                let registry = registry.clone();
                let events = checkin_events.clone();
                Box::pin(async move { handle_checkin(&registry, &events, agent_id).await })
            },
        );

        let proc_list_events = events.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandProcList),
            move |agent_id, request_id, payload| {
                let events = proc_list_events.clone();
                Box::pin(async move {
                    handle_process_list_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let proc_events = events.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandProc),
            move |agent_id, request_id, payload| {
                let events = proc_events.clone();
                Box::pin(async move {
                    handle_process_command_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let inject_events = events.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandInjectShellcode),
            move |agent_id, request_id, payload| {
                let events = inject_events.clone();
                Box::pin(async move {
                    handle_inject_shellcode_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        let token_events = events.clone();
        dispatcher.register_handler(
            u32::from(DemonCommand::CommandToken),
            move |agent_id, request_id, payload| {
                let events = token_events.clone();
                Box::pin(async move {
                    handle_token_callback(&events, agent_id, request_id, &payload).await
                })
            },
        );

        dispatcher
    }

    /// Register or replace a handler for a raw Demon command identifier.
    pub fn register_handler<F>(&mut self, command_id: u32, handler: F)
    where
        F: Fn(u32, u32, Vec<u8>) -> HandlerFuture + Send + Sync + 'static,
    {
        Arc::make_mut(&mut self.handlers).insert(command_id, Arc::new(handler));
    }

    /// Return `true` when a handler is registered for `command_id`.
    #[must_use]
    pub fn handles_command(&self, command_id: u32) -> bool {
        self.handlers.contains_key(&command_id)
    }

    /// Dispatch a single parsed callback package.
    pub async fn dispatch(
        &self,
        agent_id: u32,
        command_id: u32,
        request_id: u32,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, CommandDispatchError> {
        let Some(handler) = self.handlers.get(&command_id).cloned() else {
            return Ok(None);
        };

        handler(agent_id, request_id, payload.to_vec()).await
    }

    /// Dispatch multiple parsed callback packages and concatenate any response packages.
    pub async fn dispatch_packages(
        &self,
        agent_id: u32,
        packages: &[DemonCallbackPackage],
    ) -> Result<Vec<u8>, CommandDispatchError> {
        let mut response = Vec::new();

        for package in packages {
            if let Some(bytes) = self
                .dispatch(agent_id, package.command_id, package.request_id, &package.payload)
                .await?
            {
                response.extend_from_slice(&bytes);
            }
        }

        Ok(response)
    }
}

async fn handle_get_job(
    registry: &AgentRegistry,
    agent_id: u32,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let jobs = registry.dequeue_jobs(agent_id).await?;
    if jobs.is_empty() {
        return Ok(None);
    }

    let encryption = registry.encryption(agent_id).await?;
    let key = decode_fixed::<AGENT_KEY_LENGTH>(agent_id, "aes_key", encryption.aes_key.as_bytes())?;
    let iv = decode_fixed::<AGENT_IV_LENGTH>(agent_id, "aes_iv", encryption.aes_iv.as_bytes())?;
    let mut packages = Vec::with_capacity(jobs.len());

    for job in jobs {
        let payload = if job.payload.is_empty() {
            Vec::new()
        } else {
            encrypt_agent_data(&key, &iv, &job.payload)
        };
        packages.push(DemonPackage {
            command_id: job.command,
            request_id: job.request_id,
            payload,
        });
    }

    Ok(Some(DemonMessage::new(packages).to_bytes()?))
}

async fn handle_checkin(
    registry: &AgentRegistry,
    events: &EventBus,
    agent_id: u32,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let agent = registry.set_last_call_in(agent_id, timestamp).await?;
    events.broadcast(agent_update_event(&agent));
    Ok(None)
}

async fn handle_process_list_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandProcList));
    let _from_process_manager = parser.read_u32("process ui flag")?;
    let mut rows = Vec::new();

    while !parser.is_empty() {
        let name = parser.read_utf16("process name")?;
        let pid = parser.read_u32("process pid")?;
        let is_wow = parser.read_u32("process wow64")?;
        let ppid = parser.read_u32("process ppid")?;
        let session = parser.read_u32("process session")?;
        let threads = parser.read_u32("process threads")?;
        let user = parser.read_utf16("process user")?;
        let arch = if is_wow == 0 { "x64" } else { "x86" };
        rows.push(ProcessRow { name, pid, ppid, session, arch: arch.to_owned(), threads, user });
    }

    let output = format_process_table(&rows);
    if output.is_empty() {
        return Ok(None);
    }

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandProcList),
        request_id,
        "Info",
        "Process List:",
        Some(output),
    )?);
    Ok(None)
}

async fn handle_process_command_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandProc));
    let subcommand = parser.read_u32("process subcommand")?;

    match DemonProcessCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandProc),
            message: error.to_string(),
        }
    })? {
        DemonProcessCommand::Create => {
            let path = parser.read_utf16("process path")?;
            let pid = parser.read_u32("process pid")?;
            let success = parser.read_u32("process create success")?;
            let piped = parser.read_u32("process create piped")?;
            let verbose = parser.read_u32("process create verbose")?;

            if verbose != 0 {
                let (kind, message) = if success != 0 {
                    ("Info", format!("Process started: Path:[{path}] ProcessID:[{pid}]"))
                } else {
                    ("Error", format!("Process could not be started: Path:[{path}]"))
                };
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandProc),
                    request_id,
                    kind,
                    &message,
                    None,
                )?);
            } else if success == 0 || piped == 0 {
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandProc),
                    request_id,
                    "Info",
                    "Process create completed",
                    None,
                )?);
            }
        }
        DemonProcessCommand::Kill => {
            let success = parser.read_u32("process kill success")?;
            let pid = parser.read_u32("process kill pid")?;
            let (kind, message) = if success != 0 {
                ("Good", format!("Successful killed process: {pid}"))
            } else {
                ("Error", "Failed to kill process".to_owned())
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandProc),
                request_id,
                kind,
                &message,
                None,
            )?);
        }
        other => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandProc),
                message: format!("unsupported process callback subcommand {other:?}"),
            });
        }
    }

    Ok(None)
}

async fn handle_inject_shellcode_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandInjectShellcode));
    let status = parser.read_u32("shellcode inject status")?;
    let (kind, message) = match status {
        x if x == u32::from(DemonInjectError::Success) => ("Good", "Successful injected shellcode"),
        x if x == u32::from(DemonInjectError::Failed) => ("Error", "Failed to inject shellcode"),
        x if x == u32::from(DemonInjectError::InvalidParam) => {
            ("Error", "Invalid parameter specified")
        }
        x if x == u32::from(DemonInjectError::ProcessArchMismatch) => {
            ("Error", "Process architecture mismatch")
        }
        other => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandInjectShellcode),
                message: format!("unknown shellcode injection status {other}"),
            });
        }
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandInjectShellcode),
        request_id,
        kind,
        message,
        None,
    )?);
    Ok(None)
}

async fn handle_token_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandToken));
    let subcommand = parser.read_u32("token subcommand")?;

    match DemonTokenCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandToken),
            message: error.to_string(),
        }
    })? {
        DemonTokenCommand::Impersonate => {
            let success = parser.read_u32("token impersonation success")?;
            let user = parser.read_string("token impersonation user")?;
            let (kind, message) = if success != 0 {
                ("Good", format!("Successful impersonated {user}"))
            } else {
                ("Error", format!("Failed to impersonat {user}"))
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandToken),
                request_id,
                kind,
                &message,
                None,
            )?);
        }
        other => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandToken),
                message: format!("unsupported token callback subcommand {other:?}"),
            });
        }
    }

    Ok(None)
}

fn decode_fixed<const N: usize>(
    agent_id: u32,
    field: &'static str,
    encoded: &[u8],
) -> Result<[u8; N], CommandDispatchError> {
    let decoded = BASE64_STANDARD.decode(encoded).map_err(|error| {
        CommandDispatchError::InvalidStoredCryptoEncoding {
            agent_id,
            field,
            message: error.to_string(),
        }
    })?;

    let actual = decoded.len();
    decoded.try_into().map_err(|_| CommandDispatchError::InvalidStoredCryptoLength {
        agent_id,
        field,
        expected: N,
        actual,
    })
}

fn agent_update_event(agent: &red_cell_common::AgentInfo) -> OperatorMessage {
    OperatorMessage::AgentUpdate(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "teamserver".to_owned(),
            timestamp: agent.last_call_in.clone(),
            one_time: String::new(),
        },
        info: AgentUpdateInfo { agent_id: agent.name_id(), marked: "Alive".to_owned() },
    })
}

fn agent_response_event(
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    kind: &str,
    message: &str,
    output: Option<String>,
) -> Result<OperatorMessage, CommandDispatchError> {
    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let mut extra = BTreeMap::new();
    extra.insert("Type".to_owned(), Value::String(kind.to_owned()));
    extra.insert("Message".to_owned(), Value::String(message.to_owned()));
    extra.insert("RequestID".to_owned(), Value::String(format!("{request_id:X}")));

    Ok(OperatorMessage::AgentResponse(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "teamserver".to_owned(),
            timestamp,
            one_time: String::new(),
        },
        info: AgentResponseInfo {
            demon_id: format!("{agent_id:08X}"),
            command_id: command_id.to_string(),
            output: output.unwrap_or_default(),
            command_line: None,
            extra,
        },
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessRow {
    name: String,
    pid: u32,
    ppid: u32,
    session: u32,
    arch: String,
    threads: u32,
    user: String,
}

fn format_process_table(rows: &[ProcessRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let name_width = rows.iter().map(|row| row.name.len()).max().unwrap_or(4).max(4);
    let mut output = String::new();
    output.push_str(&format_process_row(
        name_width, "Name", "PID", "PPID", "Session", "Arch", "Threads", "User",
    ));
    output.push('\n');
    output.push_str(&format_process_row(
        name_width, "----", "---", "----", "-------", "----", "-------", "----",
    ));
    output.push('\n');

    for row in rows {
        output.push_str(&format_process_row(
            name_width,
            &row.name,
            row.pid,
            row.ppid,
            row.session,
            &row.arch,
            row.threads,
            &row.user,
        ));
        output.push('\n');
    }

    output
}

fn format_process_row(
    name_width: usize,
    name: impl std::fmt::Display,
    pid: impl std::fmt::Display,
    ppid: impl std::fmt::Display,
    session: impl std::fmt::Display,
    arch: impl std::fmt::Display,
    threads: impl std::fmt::Display,
    user: impl std::fmt::Display,
) -> String {
    format!(
        " {name:<name_width$}   {pid:<4}   {ppid:<4}   {session:<7}   {arch:<5}   {threads:<7}   {user:<4}",
        name = name,
        pid = pid,
        ppid = ppid,
        session = session,
        arch = arch,
        threads = threads,
        user = user,
        name_width = name_width,
    )
}

struct CallbackParser<'a> {
    bytes: &'a [u8],
    offset: usize,
    command_id: u32,
}

impl<'a> CallbackParser<'a> {
    fn new(bytes: &'a [u8], command_id: u32) -> Self {
        Self { bytes, offset: 0, command_id }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn read_u32(&mut self, context: &'static str) -> Result<u32, CommandDispatchError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining < 4 {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: self.command_id,
                message: format!("{context}: expected 4 bytes, got {remaining}"),
            });
        }

        let value =
            u32::from_le_bytes(self.bytes[self.offset..self.offset + 4].try_into().map_err(
                |_| CommandDispatchError::InvalidCallbackPayload {
                    command_id: self.command_id,
                    message: format!("{context}: failed to read u32"),
                },
            )?);
        self.offset += 4;
        Ok(value)
    }

    fn read_bytes(&mut self, context: &'static str) -> Result<Vec<u8>, CommandDispatchError> {
        let len = usize::try_from(self.read_u32(context)?).map_err(|_| {
            CommandDispatchError::InvalidCallbackPayload {
                command_id: self.command_id,
                message: format!("{context}: length overflow"),
            }
        })?;
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining < len {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: self.command_id,
                message: format!("{context}: expected {len} bytes, got {remaining}"),
            });
        }

        let value = self.bytes[self.offset..self.offset + len].to_vec();
        self.offset += len;
        Ok(value)
    }

    fn read_utf16(&mut self, context: &'static str) -> Result<String, CommandDispatchError> {
        let raw = self.read_bytes(context)?;
        if raw.len() % 2 != 0 {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: self.command_id,
                message: format!("{context}: utf16 length must be even"),
            });
        }

        let words = raw
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        Ok(String::from_utf16_lossy(&words).trim_end_matches('\0').to_owned())
    }

    fn read_string(&mut self, context: &'static str) -> Result<String, CommandDispatchError> {
        let raw = self.read_bytes(context)?;
        Ok(String::from_utf8_lossy(&raw).trim_end_matches('\0').to_owned())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data};
    use red_cell_common::demon::{
        DemonCommand, DemonInjectError, DemonProcessCommand, DemonTokenCommand,
    };
    use red_cell_common::operator::OperatorMessage;
    use serde_json::Value;

    use super::CommandDispatcher;
    use crate::{AgentRegistry, Database, EventBus, Job};

    fn sample_agent_info(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
    ) -> red_cell_common::AgentInfo {
        red_cell_common::AgentInfo {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: red_cell_common::AgentEncryptionInfo {
                aes_key: BASE64_STANDARD.encode(key),
                aes_iv: BASE64_STANDARD.encode(iv),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "lab".to_owned(),
            external_ip: "127.0.0.1".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            base_address: 0x1000,
            process_pid: 1337,
            process_tid: 7331,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_arch: "x64".to_owned(),
            sleep_delay: 10,
            sleep_jitter: 25,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-03-09T20:00:00Z".to_owned(),
            last_call_in: "2026-03-09T20:00:00Z".to_owned(),
        }
    }

    #[tokio::test]
    async fn dispatch_returns_none_for_unregistered_commands()
    -> Result<(), Box<dyn std::error::Error>> {
        let dispatcher = CommandDispatcher::new();

        assert_eq!(dispatcher.dispatch(0x4141_4141, 0x9999, 7, b"payload").await?, None);
        assert!(!dispatcher.handles_command(0x9999));
        Ok(())
    }

    #[tokio::test]
    async fn custom_handlers_receive_agent_request_and_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut dispatcher = CommandDispatcher::default();
        dispatcher.register_handler(0x1234, |agent_id, request_id, payload| {
            Box::pin(async move {
                let mut response = agent_id.to_le_bytes().to_vec();
                response.extend_from_slice(&request_id.to_le_bytes());
                response.extend_from_slice(&payload);
                Ok(Some(response))
            })
        });

        let response = dispatcher.dispatch(0xAABB_CCDD, 0x1234, 0x0102_0304, b"abc").await?;

        assert_eq!(
            response,
            Some([0xDD, 0xCC, 0xBB, 0xAA, 0x04, 0x03, 0x02, 0x01, b'a', b'b', b'c',].to_vec())
        );
        assert!(dispatcher.handles_command(0x1234));
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_packages_concatenates_handler_responses()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut dispatcher = CommandDispatcher::new();
        dispatcher
            .register_handler(0x1111, |_, _, _| Box::pin(async move { Ok(Some(vec![1, 2])) }));
        dispatcher
            .register_handler(0x2222, |_, _, _| Box::pin(async move { Ok(Some(vec![3, 4])) }));

        let packages = vec![
            crate::DemonCallbackPackage { command_id: 0x1111, request_id: 1, payload: Vec::new() },
            crate::DemonCallbackPackage { command_id: 0x2222, request_id: 2, payload: Vec::new() },
        ];

        assert_eq!(dispatcher.dispatch_packages(0x1234_5678, &packages).await?, vec![1, 2, 3, 4]);
        Ok(())
    }

    #[tokio::test]
    async fn builtin_get_job_handler_serializes_and_drains_jobs()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database);
        let events = EventBus::default();
        let dispatcher = CommandDispatcher::with_builtin_handlers(registry.clone(), events);
        let key = [0x55; AGENT_KEY_LENGTH];
        let iv = [0x22; AGENT_IV_LENGTH];
        let agent_id = 0x5566_7788;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        registry
            .enqueue_job(
                agent_id,
                Job {
                    command: u32::from(DemonCommand::CommandSleep),
                    request_id: 41,
                    payload: vec![1, 2, 3, 4],
                    command_line: "sleep 10".to_owned(),
                    task_id: "task-41".to_owned(),
                    created_at: "2026-03-09T20:10:00Z".to_owned(),
                },
            )
            .await?;

        let response = dispatcher
            .dispatch(agent_id, u32::from(DemonCommand::CommandGetJob), 9, &[])
            .await?
            .ok_or_else(|| "get job should return serialized packages".to_owned())?;
        let message = red_cell_common::demon::DemonMessage::from_bytes(&response)?;

        assert_eq!(message.packages.len(), 1);
        assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
        assert_eq!(message.packages[0].request_id, 41);
        assert_eq!(decrypt_agent_data(&key, &iv, &message.packages[0].payload)?, vec![1, 2, 3, 4]);
        assert!(registry.queued_jobs(agent_id).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn builtin_checkin_handler_updates_last_call_in_and_broadcasts()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database);
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let dispatcher = CommandDispatcher::with_builtin_handlers(registry.clone(), events);
        let key = [0x77; AGENT_KEY_LENGTH];
        let iv = [0x44; AGENT_IV_LENGTH];
        let agent_id = 0x1020_3040;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        let before = registry
            .get(agent_id)
            .await
            .ok_or_else(|| "agent should exist before checkin".to_owned())?
            .last_call_in;

        let response = dispatcher
            .dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &[0xAA, 0xBB])
            .await?;

        assert_eq!(response, None);

        let updated = registry
            .get(agent_id)
            .await
            .ok_or_else(|| "agent should exist after checkin".to_owned())?;
        assert_ne!(updated.last_call_in, before);

        let event = receiver
            .recv()
            .await
            .ok_or_else(|| "agent update event should be broadcast".to_owned())?;
        let OperatorMessage::AgentUpdate(message) = event else {
            panic!("unexpected operator event");
        };
        assert_eq!(message.info.agent_id, format!("{agent_id:08X}"));
        assert_eq!(message.info.marked, "Alive");
        Ok(())
    }

    #[tokio::test]
    async fn builtin_process_list_handler_broadcasts_formatted_agent_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database);
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let dispatcher = CommandDispatcher::with_builtin_handlers(registry, events);

        let mut payload = Vec::new();
        add_u32(&mut payload, 0);
        add_utf16(&mut payload, "explorer.exe");
        add_u32(&mut payload, 1337);
        add_u32(&mut payload, 0);
        add_u32(&mut payload, 512);
        add_u32(&mut payload, 1);
        add_u32(&mut payload, 17);
        add_utf16(&mut payload, "LAB\\operator");

        let response = dispatcher
            .dispatch(0xDEAD_BEEF, u32::from(DemonCommand::CommandProcList), 0x2A, &payload)
            .await?;
        assert_eq!(response, None);

        let event =
            receiver.recv().await.ok_or_else(|| "agent response event missing".to_owned())?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(message.info.demon_id, "DEADBEEF");
        assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandProcList).to_string());
        assert!(message.info.output.contains("explorer.exe"));
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Process List:".to_owned()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_process_kill_and_token_handlers_broadcast_agent_responses()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database);
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let dispatcher = CommandDispatcher::with_builtin_handlers(registry, events);

        let kill_payload = [
            u32::from(DemonProcessCommand::Kill).to_le_bytes(),
            1_u32.to_le_bytes(),
            4040_u32.to_le_bytes(),
        ]
        .concat();
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandProc), 7, &kill_payload)
            .await?;

        let event = receiver.recv().await.ok_or_else(|| "kill response missing".to_owned())?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Successful killed process: 4040".to_owned()))
        );

        let token_payload =
            [u32::from(DemonTokenCommand::Impersonate).to_le_bytes(), 1_u32.to_le_bytes()].concat();
        let mut token_payload = token_payload;
        add_bytes(&mut token_payload, b"LAB\\svc");
        dispatcher
            .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 8, &token_payload)
            .await?;

        let event = receiver.recv().await.ok_or_else(|| "token response missing".to_owned())?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Successful impersonated LAB\\svc".to_owned()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn builtin_shellcode_handler_broadcasts_agent_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database);
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let dispatcher = CommandDispatcher::with_builtin_handlers(registry, events);

        dispatcher
            .dispatch(
                0x0102_0304,
                u32::from(DemonCommand::CommandInjectShellcode),
                9,
                &u32::from(DemonInjectError::ProcessArchMismatch).to_le_bytes(),
            )
            .await?;

        let event = receiver.recv().await.ok_or_else(|| "shellcode response missing".to_owned())?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_eq!(
            message.info.extra.get("Message"),
            Some(&Value::String("Process architecture mismatch".to_owned()))
        );
        assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
        Ok(())
    }

    fn add_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn add_bytes(buf: &mut Vec<u8>, value: &[u8]) {
        add_u32(buf, u32::try_from(value.len()).unwrap_or_default());
        buf.extend_from_slice(value);
    }

    fn add_utf16(buf: &mut Vec<u8>, value: &str) {
        let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        encoded.extend_from_slice(&[0, 0]);
        add_bytes(buf, &encoded);
    }
}
