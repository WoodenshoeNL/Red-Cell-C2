//! Profile introspection endpoint.

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use crate::app::TeamserverState;
use crate::{AuditDetails, AuditResultStatus};

use super::auth::AdminApiAccess;

/// Redacted operator entry (password omitted, role shown).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub(super) struct ProfileOperatorEntry {
    name: String,
    role: String,
    has_password: bool,
}

/// Redacted API key entry (secret omitted, role shown).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub(super) struct ProfileApiKeyEntry {
    name: String,
    role: String,
}

/// Summary of a configured HTTP listener.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub(super) struct ProfileHttpListenerEntry {
    name: String,
    protocol: String,
    host_bind: String,
    port_bind: u16,
    port_conn: Option<u16>,
    hosts: Vec<String>,
    secure: bool,
}

/// Summary of a configured SMB listener.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub(super) struct ProfileSmbListenerEntry {
    name: String,
    protocol: String,
    pipe_name: String,
}

/// Summary of a configured DNS listener.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub(super) struct ProfileDnsListenerEntry {
    name: String,
    protocol: String,
    host_bind: String,
    port_bind: u16,
    domain: String,
}

/// Summary of a configured external listener.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub(super) struct ProfileExternalListenerEntry {
    name: String,
    protocol: String,
    endpoint: String,
}

/// Listener summaries across all transport types.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub(super) struct ProfileListeners {
    http: Vec<ProfileHttpListenerEntry>,
    smb: Vec<ProfileSmbListenerEntry>,
    dns: Vec<ProfileDnsListenerEntry>,
    external: Vec<ProfileExternalListenerEntry>,
}

/// Demon default settings from the profile.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub(super) struct ProfileDemonDefaults {
    sleep: Option<u64>,
    jitter: Option<u8>,
    indirect_syscall: bool,
    stack_duplication: bool,
    sleep_technique: Option<String>,
}

/// Redacted webhook status.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub(super) struct ProfileWebhookStatus {
    discord_configured: bool,
}

/// Effective teamserver profile (secrets redacted).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub(super) struct ProfileResponse {
    path: String,
    host: String,
    port: u16,
    operators: Vec<ProfileOperatorEntry>,
    api_keys: Vec<ProfileApiKeyEntry>,
    api_rate_limit_per_minute: Option<u32>,
    listeners: ProfileListeners,
    demon: ProfileDemonDefaults,
    service_configured: bool,
    webhook: Option<ProfileWebhookStatus>,
}

#[utoipa::path(
    get,
    path = "/profile",
    context_path = "/api/v1",
    tag = "rest",
    security(("api_key" = [])),
    responses(
        (status = 200, description = "Effective profile (secrets redacted)", body = ProfileResponse),
        (status = 401, description = "Missing or invalid API key", body = super::errors::ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = super::errors::ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = super::errors::ApiErrorBody)
    )
)]
pub(super) async fn get_profile(
    State(state): State<TeamserverState>,
    identity: AdminApiAccess,
) -> Json<ProfileResponse> {
    let profile = &state.profile;

    super::record_audit_entry(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        "profile.show",
        "profile",
        None,
        AuditDetails {
            agent_id: None,
            command: None,
            parameters: None,
            result_status: AuditResultStatus::Success,
        },
    )
    .await;

    let operators: Vec<ProfileOperatorEntry> = profile
        .operators
        .users
        .iter()
        .map(|(name, cfg)| ProfileOperatorEntry {
            name: name.clone(),
            role: format!("{:?}", cfg.role),
            has_password: !cfg.password.is_empty(),
        })
        .collect();

    let api_keys: Vec<ProfileApiKeyEntry> = profile
        .api
        .as_ref()
        .map(|api| {
            api.keys
                .iter()
                .map(|(name, cfg)| ProfileApiKeyEntry {
                    name: name.clone(),
                    role: format!("{:?}", cfg.role),
                })
                .collect()
        })
        .unwrap_or_default();

    let api_rate_limit_per_minute = profile.api.as_ref().map(|api| api.rate_limit_per_minute);

    let http_listeners: Vec<ProfileHttpListenerEntry> = profile
        .listeners
        .http
        .iter()
        .map(|l| ProfileHttpListenerEntry {
            name: l.name.clone(),
            protocol: if l.secure { "https".to_owned() } else { "http".to_owned() },
            host_bind: l.host_bind.clone(),
            port_bind: l.port_bind,
            port_conn: l.port_conn,
            hosts: l.hosts.clone(),
            secure: l.secure,
        })
        .collect();

    let smb_listeners: Vec<ProfileSmbListenerEntry> = profile
        .listeners
        .smb
        .iter()
        .map(|l| ProfileSmbListenerEntry {
            name: l.name.clone(),
            protocol: "smb".to_owned(),
            pipe_name: l.pipe_name.clone(),
        })
        .collect();

    let dns_listeners: Vec<ProfileDnsListenerEntry> = profile
        .listeners
        .dns
        .iter()
        .map(|l| ProfileDnsListenerEntry {
            name: l.name.clone(),
            protocol: "dns".to_owned(),
            host_bind: l.host_bind.clone(),
            port_bind: l.port_bind,
            domain: l.domain.clone(),
        })
        .collect();

    let external_listeners: Vec<ProfileExternalListenerEntry> = profile
        .listeners
        .external
        .iter()
        .map(|l| ProfileExternalListenerEntry {
            name: l.name.clone(),
            protocol: "external".to_owned(),
            endpoint: l.endpoint.clone(),
        })
        .collect();

    let webhook = profile
        .webhook
        .as_ref()
        .map(|wh| ProfileWebhookStatus { discord_configured: wh.discord.is_some() });

    Json(ProfileResponse {
        path: state.profile_path.clone(),
        host: profile.teamserver.host.clone(),
        port: profile.teamserver.port,
        operators,
        api_keys,
        api_rate_limit_per_minute,
        listeners: ProfileListeners {
            http: http_listeners,
            smb: smb_listeners,
            dns: dns_listeners,
            external: external_listeners,
        },
        demon: ProfileDemonDefaults {
            sleep: profile.demon.sleep,
            jitter: profile.demon.jitter,
            indirect_syscall: profile.demon.indirect_syscall,
            stack_duplication: profile.demon.stack_duplication,
            sleep_technique: profile.demon.sleep_technique.clone(),
        },
        service_configured: profile.service.is_some(),
        webhook,
    })
}
