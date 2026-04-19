//! Operator WebSocket handler for `BuildPayloadRequest`.
//!
//! The build itself runs in a background task so the operator WebSocket loop
//! is not blocked while the compiler runs.

use red_cell_common::ListenerConfig;
use red_cell_common::operator::{BuildPayloadRequestInfo, Message};
use serde_json::Value;

use super::serialize_for_audit;
use crate::websocket::events::{
    build_payload_message_event, build_payload_response_event, format_diagnostic,
};
use crate::websocket::lifecycle::log_operator_action;
use crate::{
    AuditResultStatus, AuditWebhookNotifier, Database, EventBus, ListenerManager,
    PayloadBuildError, PayloadBuilderService, audit_details, authorize_listener_access,
    parameter_object,
};

pub(super) async fn handle_build_payload_request(
    listeners: &ListenerManager,
    payload_builder: &PayloadBuilderService,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    session: &crate::OperatorSession,
    message: Message<BuildPayloadRequestInfo>,
) {
    let actor = session.username.clone();
    let events = events.clone();
    let listeners = listeners.clone();
    let payload_builder = payload_builder.clone();
    let database = database.clone();
    let webhooks = webhooks.clone();
    let listener_name = message.info.listener.clone();
    let arch = message.info.arch.clone();
    let format = message.info.format.clone();

    if let Err(error) = authorize_listener_access(&database, &actor, &listener_name).await {
        events.broadcast(build_payload_message_event(&actor, "Error", &error.to_string()));
        log_operator_action(
            &database,
            &webhooks,
            &actor,
            "payload.build",
            "payload",
            Some(listener_name.clone()),
            audit_details(
                AuditResultStatus::Failure,
                None,
                None,
                Some(parameter_object([
                    ("listener", Value::String(listener_name.clone())),
                    ("arch", Value::String(arch.clone())),
                    ("format", Value::String(format.clone())),
                    ("error", Value::String(error.to_string())),
                ])),
            ),
        )
        .await;
        return;
    }

    tokio::spawn(async move {
        let summary = match listeners.summary(&listener_name).await {
            Ok(summary) => summary,
            Err(error) => {
                events.broadcast(build_payload_message_event(&actor, "Error", &error.to_string()));
                return;
            }
        };

        // For Archon builds targeting non-legacy listeners, load the ECDH public
        // key so the compiler can embed it in the binary.  A DB error here is
        // fatal: we must not silently fall back to plaintext key exchange.
        let ecdh_pub_key = match archon_ecdh_pub_key_for_build(
            &message.info.agent_type,
            &summary.config,
            &listener_name,
            &database,
        )
        .await
        {
            Ok(key) => key,
            Err(msg) => {
                events.broadcast(build_payload_message_event(&actor, "Error", &msg));
                return;
            }
        };

        match payload_builder
            .build_payload(&summary.config, &message.info, ecdh_pub_key, |entry| {
                events.broadcast(build_payload_message_event(&actor, &entry.level, &entry.message));
            })
            .await
        {
            Ok(artifact) => {
                events.broadcast(build_payload_response_event(
                    &actor,
                    &artifact.file_name,
                    &artifact.format,
                    artifact.bytes.as_slice(),
                ));
                log_operator_action(
                    &database,
                    &webhooks,
                    &actor,
                    "payload.build",
                    "payload",
                    Some(listener_name.clone()),
                    audit_details(
                        AuditResultStatus::Success,
                        None,
                        None,
                        Some(parameter_object([
                            ("listener", Value::String(listener_name)),
                            ("arch", Value::String(arch)),
                            ("format", Value::String(format)),
                        ])),
                    ),
                )
                .await;
            }
            Err(error) => {
                events.broadcast(build_payload_message_event(&actor, "Error", &error.to_string()));

                let diagnostic_params =
                    if let PayloadBuildError::CommandFailed { ref diagnostics, .. } = error {
                        for diag in diagnostics {
                            events.broadcast(build_payload_message_event(
                                &actor,
                                match diag.severity.as_str() {
                                    "error" | "fatal error" => "Error",
                                    "warning" => "Warning",
                                    _ => "Info",
                                },
                                &format_diagnostic(diag),
                            ));
                        }
                        serialize_for_audit(diagnostics, "payload.build.diagnostics")
                    } else {
                        None
                    };

                log_operator_action(
                    &database,
                    &webhooks,
                    &actor,
                    "payload.build",
                    "payload",
                    Some(listener_name.clone()),
                    audit_details(
                        AuditResultStatus::Failure,
                        None,
                        None,
                        Some(parameter_object(
                            [
                                ("listener", Value::String(listener_name)),
                                ("arch", Value::String(arch)),
                                ("format", Value::String(format)),
                                ("error", Value::String(error.to_string())),
                            ]
                            .into_iter()
                            .chain(diagnostic_params.into_iter().map(|d| ("diagnostics", d))),
                        )),
                    ),
                )
                .await;
            }
        }
    });
}

/// Return the listener's X25519 public key when this is an Archon build for a
/// non-legacy HTTP listener.  Returns `Ok(None)` for non-Archon / legacy builds.
/// Returns `Err` when the keypair cannot be loaded for a build that requires it —
/// the caller must abort the build rather than fall back to plaintext key exchange.
async fn archon_ecdh_pub_key_for_build(
    agent_type: &str,
    listener_config: &ListenerConfig,
    listener_name: &str,
    database: &Database,
) -> Result<Option<[u8; 32]>, String> {
    let is_archon = agent_type.eq_ignore_ascii_case("Archon");
    let is_non_legacy_http = matches!(
        listener_config,
        ListenerConfig::Http(http) if !http.legacy_mode
    );

    if !is_archon || !is_non_legacy_http {
        return Ok(None);
    }

    match database.ecdh().get_or_create_keypair(listener_name).await {
        Ok(kp) => Ok(Some(kp.public_bytes)),
        Err(err) => {
            tracing::error!(
                listener = listener_name,
                error = %err,
                "failed to load ECDH keypair for Archon build — refusing to build without ECDH"
            );
            Err(format!("failed to load ECDH keypair for listener '{}': {err}", listener_name))
        }
    }
}
