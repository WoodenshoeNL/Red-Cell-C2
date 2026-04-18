//! Demon transport processing: init, reconnect, and callback dispatch.

use std::net::IpAddr;

use tracing::{debug, warn};

use crate::listeners::{
    DemonInitRateLimiter, ListenerManagerError, MAX_RECONNECT_PROBES_PER_AGENT,
    RECONNECT_PROBE_WINDOW_DURATION, ReconnectProbeRateLimiter, UnknownCallbackProbeAuditLimiter,
};
use crate::{
    AgentRegistry, AuditResultStatus, CommandDispatchError, CommandDispatcher, Database,
    DemonCallbackPackage, DemonPacketParser, DemonParserError, ParsedDemonPacket, PluginRuntime,
    TeamserverError,
    agent_events::{agent_new_event, agent_reregistered_event},
    audit_details, build_init_ack, build_reconnect_ack,
    events::EventBus,
    parameter_object, record_operator_action,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DemonHttpDisposition {
    Ok,
    Fake404,
    TooManyRequests,
}

#[derive(Clone, Debug)]
pub(crate) struct ProcessedDemonResponse {
    pub(crate) agent_id: u32,
    pub(crate) payload: Vec<u8>,
    pub(crate) http_disposition: DemonHttpDisposition,
}

pub(crate) fn map_command_dispatch_error(error: CommandDispatchError) -> ListenerManagerError {
    ListenerManagerError::InvalidConfig { message: error.to_string() }
}

async fn build_callback_response(
    dispatcher: &CommandDispatcher,
    agent_id: u32,
    packages: &[DemonCallbackPackage],
) -> Result<Vec<u8>, ListenerManagerError> {
    dispatcher.dispatch_packages(agent_id, packages).await.map_err(map_command_dispatch_error)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn process_demon_transport(
    listener_name: &str,
    registry: &AgentRegistry,
    database: &Database,
    parser: &DemonPacketParser,
    events: &EventBus,
    dispatcher: &CommandDispatcher,
    unknown_callback_probe_audit_limiter: &UnknownCallbackProbeAuditLimiter,
    reconnect_probe_rate_limiter: &ReconnectProbeRateLimiter,
    demon_init_rate_limiter: &DemonInitRateLimiter,
    body: &[u8],
    external_ip: String,
) -> Result<ProcessedDemonResponse, ListenerManagerError> {
    match parser.parse_for_listener(body, external_ip.as_str(), listener_name).await {
        Ok(ParsedDemonPacket::Init(init)) => {
            let response =
                build_init_ack(registry, init.agent.agent_id).await.map_err(|error| {
                    ListenerManagerError::InvalidConfig {
                        message: format!("failed to build demon init ack: {error}"),
                    }
                })?;

            let pivots = registry.pivots(init.agent.agent_id).await;
            events.broadcast(agent_new_event(
                listener_name,
                init.header.magic,
                &init.agent,
                &pivots,
            ));
            let agent_id = init.agent.agent_id;
            let external_ip_for_audit = external_ip.clone();
            let listener_name_for_audit = listener_name.to_owned();
            if let Err(error) = record_operator_action(
                database,
                "teamserver",
                "agent.registered",
                "agent",
                Some(format!("{agent_id:08X}")),
                audit_details(
                    AuditResultStatus::Success,
                    Some(agent_id),
                    Some("registered"),
                    Some(parameter_object([
                        ("listener", serde_json::Value::String(listener_name_for_audit)),
                        ("external_ip", serde_json::Value::String(external_ip_for_audit)),
                    ])),
                ),
            )
            .await
            {
                warn!(
                    listener = listener_name,
                    agent_id = format_args!("{agent_id:08X}"),
                    %error,
                    "failed to persist agent.registered audit entry"
                );
            }
            if let Ok(Some(plugins)) = PluginRuntime::current() {
                if let Err(error) = plugins.emit_agent_registered(agent_id).await {
                    tracing::warn!(
                        agent_id = format_args!("{agent_id:08X}"),
                        %error,
                        "failed to emit python agent_registered event"
                    );
                }
            }
            Ok(ProcessedDemonResponse {
                agent_id,
                payload: response,
                http_disposition: DemonHttpDisposition::Ok,
            })
        }
        Ok(ParsedDemonPacket::ReInit(init)) => {
            let response =
                build_init_ack(registry, init.agent.agent_id).await.map_err(|error| {
                    ListenerManagerError::InvalidConfig {
                        message: format!(
                            "failed to build demon init ack for re-registration: {error}"
                        ),
                    }
                })?;

            let pivots = registry.pivots(init.agent.agent_id).await;
            events.broadcast(agent_reregistered_event(
                listener_name,
                init.header.magic,
                &init.agent,
                &pivots,
            ));
            let agent_id = init.agent.agent_id;
            let external_ip_for_audit = external_ip.clone();
            let listener_name_for_audit = listener_name.to_owned();
            if let Err(error) = record_operator_action(
                database,
                "teamserver",
                "agent.reregistered",
                "agent",
                Some(format!("{agent_id:08X}")),
                audit_details(
                    AuditResultStatus::Success,
                    Some(agent_id),
                    Some("reregistered"),
                    Some(parameter_object([
                        ("listener", serde_json::Value::String(listener_name_for_audit)),
                        ("external_ip", serde_json::Value::String(external_ip_for_audit)),
                    ])),
                ),
            )
            .await
            {
                warn!(
                    listener = listener_name,
                    agent_id = format_args!("{agent_id:08X}"),
                    %error,
                    "failed to persist agent.reregistered audit entry"
                );
            }
            if let Ok(Some(plugins)) = PluginRuntime::current() {
                if let Err(error) = plugins.emit_agent_registered(agent_id).await {
                    tracing::warn!(
                        agent_id = format_args!("{agent_id:08X}"),
                        %error,
                        "failed to emit python agent_registered event for re-registration"
                    );
                }
            }
            Ok(ProcessedDemonResponse {
                agent_id,
                payload: response,
                http_disposition: DemonHttpDisposition::Ok,
            })
        }
        Ok(ParsedDemonPacket::Reconnect { header, .. }) => {
            let agent_known = registry.get(header.agent_id).await.is_some();

            if agent_known {
                if !reconnect_probe_rate_limiter.allow(header.agent_id).await {
                    warn!(
                        listener = listener_name,
                        agent_id = format_args!("{:08X}", header.agent_id),
                        external_ip,
                        max_probes = MAX_RECONNECT_PROBES_PER_AGENT,
                        window_seconds = RECONNECT_PROBE_WINDOW_DURATION.as_secs(),
                        "reconnect probe rate limit exceeded — possible probe spam"
                    );
                    return Ok(ProcessedDemonResponse {
                        agent_id: header.agent_id,
                        payload: Vec::new(),
                        http_disposition: DemonHttpDisposition::TooManyRequests,
                    });
                }

                let payload =
                    build_reconnect_ack(registry, header.agent_id).await.map_err(|error| {
                        ListenerManagerError::InvalidConfig {
                            message: format!("failed to build reconnect ack: {error}"),
                        }
                    })?;
                Ok(ProcessedDemonResponse {
                    agent_id: header.agent_id,
                    payload,
                    http_disposition: DemonHttpDisposition::Ok,
                })
            } else {
                let ip: IpAddr =
                    external_ip.parse().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                if !demon_init_rate_limiter.allow(ip).await {
                    warn!(
                        listener = listener_name,
                        agent_id = format_args!("{:08X}", header.agent_id),
                        external_ip,
                        "unknown-agent reconnect probe rejected by per-IP rate limiter"
                    );
                    return Ok(ProcessedDemonResponse {
                        agent_id: header.agent_id,
                        payload: Vec::new(),
                        http_disposition: DemonHttpDisposition::Fake404,
                    });
                }

                if unknown_callback_probe_audit_limiter.allow(listener_name, &external_ip).await {
                    warn!(
                        listener = listener_name,
                        agent_id = format_args!("{:08X}", header.agent_id),
                        external_ip,
                        "unknown agent sent reconnect probe"
                    );
                    record_unknown_reconnect_probe(
                        database,
                        listener_name,
                        header.agent_id,
                        &external_ip,
                    )
                    .await;
                } else {
                    debug!(
                        listener = listener_name,
                        agent_id = format_args!("{:08X}", header.agent_id),
                        external_ip,
                        "suppressing unknown reconnect probe audit row after per-source limit"
                    );
                }
                Ok(ProcessedDemonResponse {
                    agent_id: header.agent_id,
                    payload: Vec::new(),
                    http_disposition: DemonHttpDisposition::Fake404,
                })
            }
        }
        Ok(ParsedDemonPacket::Callback { header, packages }) => {
            let payload = build_callback_response(dispatcher, header.agent_id, &packages).await?;

            Ok(ProcessedDemonResponse {
                agent_id: header.agent_id,
                payload,
                http_disposition: DemonHttpDisposition::Ok,
            })
        }
        Err(DemonParserError::Registry(TeamserverError::AgentNotFound { agent_id })) => {
            if unknown_callback_probe_audit_limiter.allow(listener_name, &external_ip).await {
                warn!(
                    listener = listener_name,
                    agent_id = format_args!("{:08X}", agent_id),
                    external_ip,
                    "unknown agent sent callback probe"
                );
                record_unknown_callback_probe(database, listener_name, agent_id, &external_ip)
                    .await;
            } else {
                debug!(
                    listener = listener_name,
                    agent_id = format_args!("{:08X}", agent_id),
                    external_ip,
                    "suppressing unknown callback probe audit row after per-source limit"
                );
            }
            Ok(ProcessedDemonResponse {
                agent_id,
                payload: Vec::new(),
                http_disposition: DemonHttpDisposition::Fake404,
            })
        }
        Err(error) => Err(ListenerManagerError::InvalidConfig {
            message: format!("failed to parse demon callback: {error}"),
        }),
    }
}

async fn record_unknown_reconnect_probe(
    database: &Database,
    listener_name: &str,
    agent_id: u32,
    external_ip: &str,
) {
    let details = audit_details(
        AuditResultStatus::Failure,
        Some(agent_id),
        Some("reconnect_probe"),
        Some(parameter_object([
            ("listener", serde_json::Value::String(listener_name.to_owned())),
            ("external_ip", serde_json::Value::String(external_ip.to_owned())),
        ])),
    );

    if let Err(error) = record_operator_action(
        database,
        "teamserver",
        "agent.reconnect_probe",
        "agent",
        Some(format!("{agent_id:08X}")),
        details,
    )
    .await
    {
        warn!(
            listener = listener_name,
            agent_id = format_args!("{agent_id:08X}"),
            %error,
            "failed to persist unknown reconnect probe audit entry"
        );
    }
}

async fn record_unknown_callback_probe(
    database: &Database,
    listener_name: &str,
    agent_id: u32,
    external_ip: &str,
) {
    let details = audit_details(
        AuditResultStatus::Failure,
        Some(agent_id),
        Some("callback_probe"),
        Some(parameter_object([
            ("listener", serde_json::Value::String(listener_name.to_owned())),
            ("external_ip", serde_json::Value::String(external_ip.to_owned())),
        ])),
    );

    if let Err(error) = record_operator_action(
        database,
        "teamserver",
        "agent.callback_probe",
        "agent",
        Some(format!("{agent_id:08X}")),
        details,
    )
    .await
    {
        warn!(
            listener = listener_name,
            agent_id = format_args!("{agent_id:08X}"),
            %error,
            "failed to persist unknown callback probe audit entry"
        );
    }
}
