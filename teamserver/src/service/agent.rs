use axum::extract::ws::{Message as WsMessage, WebSocket};
use red_cell_common::demon::DEMON_MAGIC_VALUE;
use red_cell_common::operator::{
    AgentResponseInfo, EventCode, Message, MessageHead, OperatorMessage,
    ServiceAgentRegistrationInfo,
};
use serde_json::Value;
use time::OffsetDateTime;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::agent_events::agent_new_event;
use crate::audit::{AuditResultStatus, audit_details};
use crate::sockets::AgentSocketSnapshot;
use crate::{AgentRegistry, AuditWebhookNotifier, Database, EventBus, PivotInfo};

use super::logging::{log_service_action, service_log_event};
use super::{
    BODY_AGENT_OUTPUT, BODY_AGENT_REGISTER, BODY_AGENT_RESPONSE, BODY_AGENT_TASK, ServiceBridge,
    ServiceBridgeError,
};

/// Handle a `RegisterAgent` message — register a custom agent type with the
/// teamserver so operators can see it in their UI.
pub(super) async fn handle_register_agent(
    message: &Value,
    bridge: &ServiceBridge,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    client_agents: &mut Vec<String>,
) -> Result<(), ServiceBridgeError> {
    let agent_data = message
        .get("Body")
        .and_then(|b| b.get("Agent"))
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Agent".to_owned()))?;

    let agent_name = agent_data
        .get("Name")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Agent.Name".to_owned()))?;

    bridge.register_agent(agent_name.to_owned()).await?;
    client_agents.push(agent_name.to_owned());

    info!(name = %agent_name, "service agent registered");

    log_service_action(
        database,
        webhooks,
        "service.register_agent",
        "agent_type",
        Some(agent_name.to_owned()),
        audit_details(AuditResultStatus::Success, None, None, None),
    )
    .await;

    let agent_json = serde_json::to_string(agent_data)?;
    let event = OperatorMessage::ServiceAgentRegister(Message {
        head: MessageHead {
            event: EventCode::Service,
            user: String::new(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: ServiceAgentRegistrationInfo { agent: agent_json },
    });
    events.broadcast(event);

    Ok(())
}

/// Handle an `Agent` message — dispatches to sub-handlers based on `Body.Type`.
pub(super) async fn handle_agent_message(
    message: &Value,
    _bridge: &ServiceBridge,
    events: &EventBus,
    agent_registry: &AgentRegistry,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    socket: &mut WebSocket,
) -> Result<(), ServiceBridgeError> {
    let body_type =
        message.get("Body").and_then(|b| b.get("Type")).and_then(Value::as_str).unwrap_or_default();

    match body_type {
        BODY_AGENT_TASK => {
            handle_agent_task(message, events, agent_registry, database, webhooks, socket).await
        }
        BODY_AGENT_REGISTER => {
            handle_agent_instance_register(message, events, agent_registry, database, webhooks)
                .await
        }
        BODY_AGENT_RESPONSE => handle_agent_response(message, events).await,
        BODY_AGENT_OUTPUT => handle_agent_output(message, events).await,
        other => {
            debug!(body_type = %other, "unknown service agent sub-message type");
            Ok(())
        }
    }
}

/// Handle an `AgentTask` message — queue or retrieve tasks for a registered agent.
///
/// Supports two task modes matching the original Havoc protocol:
/// - `"Add"`: decode the base64-encoded command and enqueue a job for the agent
/// - `"Get"`: drain the agent's job queue and return combined payloads as base64
pub(super) async fn handle_agent_task(
    message: &Value,
    events: &EventBus,
    agent_registry: &AgentRegistry,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    socket: &mut WebSocket,
) -> Result<(), ServiceBridgeError> {
    let body =
        message.get("Body").ok_or_else(|| ServiceBridgeError::MissingField("Body".to_owned()))?;

    let agent_info = body
        .get("Agent")
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Agent".to_owned()))?;

    let agent_id_str = agent_info
        .get("NameID")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Agent.NameID".to_owned()))?;

    let agent_id = u32::from_str_radix(agent_id_str, 16).map_err(|_| {
        ServiceBridgeError::MissingField(format!("Body.Agent.NameID: invalid hex '{agent_id_str}'"))
    })?;

    let task = body
        .get("Task")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Task".to_owned()))?;

    match task {
        "Add" => {
            let command_b64 = body
                .get("Command")
                .and_then(Value::as_str)
                .ok_or_else(|| ServiceBridgeError::MissingField("Body.Command".to_owned()))?;

            use base64::Engine as _;
            let payload = base64::engine::general_purpose::STANDARD
                .decode(command_b64)
                .map_err(|e| ServiceBridgeError::Base64Decode(e.to_string()))?;

            let job = crate::agents::Job {
                command: 0,
                request_id: 0,
                payload,
                command_line: String::new(),
                task_id: Uuid::new_v4().to_string(),
                created_at: OffsetDateTime::now_utc().unix_timestamp().to_string(),
                operator: "service".to_owned(),
            };

            agent_registry.enqueue_job(agent_id, job).await?;
            info!(agent_id = %agent_id_str, "service agent task enqueued");

            log_service_action(
                database,
                webhooks,
                "service.agent_task",
                "agent",
                Some(agent_id_str.to_owned()),
                audit_details(AuditResultStatus::Success, Some(agent_id), Some("Add"), None),
            )
            .await;

            let log_event =
                service_log_event(&format!("task enqueued for agent {agent_id_str} via service"));
            events.broadcast(log_event);
            Ok(())
        }
        "Get" => {
            let jobs = agent_registry.dequeue_jobs(agent_id).await?;

            let mut combined_payload = Vec::new();
            for job in &jobs {
                combined_payload.extend_from_slice(&job.payload);
            }

            use base64::Engine as _;
            let encoded = base64::engine::general_purpose::STANDARD.encode(&combined_payload);

            let mut response = message.clone();
            if let Some(resp_body) = response.get_mut("Body") {
                resp_body["TasksQueue"] = Value::String(encoded);
            }

            let response_text = serde_json::to_string(&response)?;
            socket
                .send(WsMessage::Text(response_text.into()))
                .await
                .map_err(ServiceBridgeError::WebSocket)?;

            debug!(agent_id = %agent_id_str, count = jobs.len(), "service agent tasks returned");
            Ok(())
        }
        other => {
            debug!(task = %other, "unknown service agent task mode");
            Ok(())
        }
    }
}

/// Handle an `AgentRegister` message — register a new agent instance through the
/// service bridge.
///
/// Parses the registration info from the message body, constructs an `AgentRecord`,
/// inserts it into the agent registry, and broadcasts an `AgentNew` event to operators.
pub(super) async fn handle_agent_instance_register(
    message: &Value,
    events: &EventBus,
    agent_registry: &AgentRegistry,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
) -> Result<(), ServiceBridgeError> {
    let body =
        message.get("Body").ok_or_else(|| ServiceBridgeError::MissingField("Body".to_owned()))?;

    let register_info = body
        .get("RegisterInfo")
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.RegisterInfo".to_owned()))?;

    let agent_header = body
        .get("AgentHeader")
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.AgentHeader".to_owned()))?;

    let agent_id_str = agent_header
        .get("AgentID")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.AgentHeader.AgentID".to_owned()))?;

    let agent_id = u32::from_str_radix(agent_id_str, 16).map_err(|_| {
        ServiceBridgeError::MissingField(format!(
            "Body.AgentHeader.AgentID: invalid hex '{agent_id_str}'"
        ))
    })?;

    let magic_value_str =
        agent_header.get("MagicValue").and_then(Value::as_str).ok_or_else(|| {
            ServiceBridgeError::MissingField("Body.AgentHeader.MagicValue".to_owned())
        })?;

    let magic_value = u32::from_str_radix(magic_value_str, 16).map_err(|_| {
        ServiceBridgeError::MissingField(format!(
            "Body.AgentHeader.MagicValue: invalid hex '{magic_value_str}'"
        ))
    })?;

    if magic_value != DEMON_MAGIC_VALUE {
        return Err(ServiceBridgeError::InvalidMagicValue {
            expected: DEMON_MAGIC_VALUE,
            actual: magic_value,
        });
    }

    let now = OffsetDateTime::now_utc().unix_timestamp().to_string();

    let agent = red_cell_common::AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: red_cell_common::AgentEncryptionInfo::default(),
        hostname: register_info
            .get("Hostname")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        username: register_info
            .get("Username")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        domain_name: register_info
            .get("DomainName")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        external_ip: register_info
            .get("ExternalIP")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        internal_ip: register_info
            .get("InternalIP")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        process_name: register_info
            .get("ProcessName")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        process_path: register_info
            .get("ProcessPath")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        base_address: 0,
        process_pid: {
            let v = register_info.get("ProcessPID").and_then(Value::as_u64).unwrap_or(0);
            match u32::try_from(v) {
                Ok(n) => n,
                Err(_) => {
                    warn!(
                        agent_id,
                        field = "ProcessPID",
                        value = v,
                        "service bridge: u64 value exceeds u32::MAX, clamping to 0"
                    );
                    0
                }
            }
        },
        process_tid: 0,
        process_ppid: 0,
        process_arch: register_info
            .get("ProcessArch")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        elevated: register_info.get("Elevated").and_then(Value::as_bool).unwrap_or(false),
        os_version: register_info
            .get("OSVersion")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        os_build: 0,
        os_arch: register_info.get("OSArch").and_then(Value::as_str).unwrap_or_default().to_owned(),
        sleep_delay: {
            let v = register_info.get("SleepDelay").and_then(Value::as_u64).unwrap_or(0);
            match u32::try_from(v) {
                Ok(n) => n,
                Err(_) => {
                    warn!(
                        agent_id,
                        field = "SleepDelay",
                        value = v,
                        "service bridge: u64 value exceeds u32::MAX, clamping to 0"
                    );
                    0
                }
            }
        },
        sleep_jitter: {
            let v = register_info.get("SleepJitter").and_then(Value::as_u64).unwrap_or(0);
            match u32::try_from(v) {
                Ok(n) => n,
                Err(_) => {
                    warn!(
                        agent_id,
                        field = "SleepJitter",
                        value = v,
                        "service bridge: u64 value exceeds u32::MAX, clamping to 0"
                    );
                    0
                }
            }
        },
        kill_date: None,
        working_hours: None,
        first_call_in: now.clone(),
        last_call_in: now,
        archon_magic: None,
    };

    let pivots = PivotInfo::default();
    let event =
        agent_new_event("service", magic_value, &agent, &pivots, AgentSocketSnapshot::default());

    agent_registry.insert(agent).await?;
    info!(agent_id = %agent_id_str, "service agent instance registered");

    log_service_action(
        database,
        webhooks,
        "service.agent_register",
        "agent",
        Some(agent_id_str.to_owned()),
        audit_details(AuditResultStatus::Success, Some(agent_id), None, None),
    )
    .await;

    events.broadcast(event);

    Ok(())
}

/// Handle agent output messages — broadcast callback data to operators.
///
/// The `Callback` field carries the actual command output from the service
/// agent.  Previous code discarded this data and only emitted a generic log
/// line.  We now forward the callback as an `AgentResponse` event so that
/// connected operators receive the payload, matching the pattern used by
/// `handle_agent_response`.
pub(super) async fn handle_agent_output(
    message: &Value,
    events: &EventBus,
) -> Result<(), ServiceBridgeError> {
    let body =
        message.get("Body").ok_or_else(|| ServiceBridgeError::MissingField("Body".to_owned()))?;

    let agent_id = body.get("AgentID").and_then(Value::as_str).unwrap_or("unknown");

    let callback = body.get("Callback");

    debug!(%agent_id, ?callback, "service agent output");

    let output = match callback {
        Some(v) => match v.as_str() {
            Some(s) => s.to_owned(),
            None => serde_json::to_string(v).unwrap_or_default(),
        },
        None => String::new(),
    };

    let response_event = OperatorMessage::AgentResponse(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "service".to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: AgentResponseInfo {
            demon_id: agent_id.to_owned(),
            command_id: String::new(),
            output,
            command_line: None,
            extra: Default::default(),
        },
    });
    events.broadcast(response_event);

    Ok(())
}

/// Handle an `AgentResponse` message — extract response data from a service
/// client and broadcast it to connected operators.
///
/// The Havoc service protocol sends responses with the following body fields:
/// - `Agent.NameID` — hex agent identifier
/// - `Response` — base64-encoded response payload
/// - `RandID` — correlation identifier for request-response pairing
pub(super) async fn handle_agent_response(
    message: &Value,
    events: &EventBus,
) -> Result<(), ServiceBridgeError> {
    let body =
        message.get("Body").ok_or_else(|| ServiceBridgeError::MissingField("Body".to_owned()))?;

    let agent_id = body
        .get("Agent")
        .and_then(|a| a.get("NameID"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    let response_data = body.get("Response").and_then(Value::as_str).unwrap_or_default();

    let rand_id = body.get("RandID").and_then(Value::as_str).unwrap_or_default();

    debug!(%agent_id, %rand_id, response_len = response_data.len(), "service agent response");

    let event = OperatorMessage::AgentResponse(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "service".to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: AgentResponseInfo {
            demon_id: agent_id.to_owned(),
            command_id: rand_id.to_owned(),
            output: response_data.to_owned(),
            command_line: None,
            extra: Default::default(),
        },
    });
    events.broadcast(event);

    Ok(())
}
