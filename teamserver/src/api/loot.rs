//! Loot, credential, and queued-job REST handlers.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::{IntoParams, ToSchema};

use crate::agents::QueuedJob;
use crate::app::TeamserverState;
use crate::database::LootFilter;
use crate::{AuthorizationError, LootRecord, TeamserverError};

use super::agents::{authorize_agent_access, operator_may_access_agent};
use super::{ApiErrorBody, ReadApiAccess, TaskAgentApiAccess, json_error_response, now_rfc3339, record_audit_entry};
use crate::{AuditResultStatus, parameter_object};

/// Upper bound on rows fetched from the loot table when ACL filtering is
/// applied in-memory.  Pagination happens after the ACL filter so callers see
/// `total` for rows they may access, not the raw row count.
const ACL_FILTER_ROW_CAP: i64 = 5_000;

// ── Loot DTOs ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub(super) struct LootSummary {
    id: i64,
    agent_id: String,
    kind: String,
    name: String,
    file_path: Option<String>,
    size_bytes: Option<i64>,
    captured_at: String,
    has_data: bool,
    operator: Option<String>,
    command_line: Option<String>,
    task_id: Option<String>,
    metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub(super) struct LootPage {
    total: usize,
    limit: usize,
    offset: usize,
    items: Vec<LootSummary>,
}

#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub(super) struct LootQuery {
    kind: Option<String>,
    agent_id: Option<String>,
    operator: Option<String>,
    command: Option<String>,
    name: Option<String>,
    file_path: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

impl LootQuery {
    pub(super) const DEFAULT_LIMIT: usize = 50;
    const MAX_LIMIT: usize = 200;

    fn limit(&self) -> usize {
        self.limit.unwrap_or(Self::DEFAULT_LIMIT).clamp(1, Self::MAX_LIMIT)
    }

    fn offset(&self) -> usize {
        self.offset.unwrap_or_default()
    }
}

// ── Credential DTOs ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub(super) struct CredentialSummary {
    id: i64,
    agent_id: String,
    name: String,
    captured_at: String,
    operator: Option<String>,
    command_line: Option<String>,
    task_id: Option<String>,
    pattern: Option<String>,
    content: Option<String>,
    metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub(super) struct CredentialPage {
    total: usize,
    limit: usize,
    offset: usize,
    items: Vec<CredentialSummary>,
}

#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub(super) struct CredentialQuery {
    agent_id: Option<String>,
    operator: Option<String>,
    command: Option<String>,
    name: Option<String>,
    pattern: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

impl CredentialQuery {
    pub(super) const DEFAULT_LIMIT: usize = 50;
    const MAX_LIMIT: usize = 200;

    fn limit(&self) -> usize {
        self.limit.unwrap_or(Self::DEFAULT_LIMIT).clamp(1, Self::MAX_LIMIT)
    }

    fn offset(&self) -> usize {
        self.offset.unwrap_or_default()
    }
}

// ── Job DTOs ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct JobSummary {
    agent_id: String,
    command_id: u32,
    request_id: String,
    task_id: String,
    command_line: String,
    created_at: String,
    operator: Option<String>,
    payload_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct JobPage {
    total: usize,
    limit: usize,
    offset: usize,
    items: Vec<JobSummary>,
}

#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub(super) struct JobQuery {
    agent_id: Option<String>,
    operator: Option<String>,
    command: Option<String>,
    task_id: Option<String>,
    request_id: Option<String>,
    command_id: Option<u32>,
    limit: Option<usize>,
    offset: Option<usize>,
}

impl JobQuery {
    const DEFAULT_LIMIT: usize = 50;
    const MAX_LIMIT: usize = 200;

    fn limit(&self) -> usize {
        self.limit.unwrap_or(Self::DEFAULT_LIMIT).clamp(1, Self::MAX_LIMIT)
    }

    fn offset(&self) -> usize {
        self.offset.unwrap_or_default()
    }
}


// ── Credential ingest DTOs ────────────────────────────────────────────────────

/// Request body for `POST /credentials` (external tool ingest).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
pub(super) struct CreateCredentialBody {
    /// Free-form principal label, e.g. `RED-CELL-WINDOW\\smbprobe`.
    #[schema(example = "CORP\\jdoe")]
    pub name: String,
    /// Credential content: password, `LM:NT` hash pair, ticket, key, ...
    pub content: String,
    /// Credential kind label (`password`, `ntlm-hash`, ...).
    #[schema(example = "password")]
    pub kind: Option<String>,
    /// Source host the credential was validated against.
    pub host: Option<String>,
    /// Source protocol (`smb`, `winrm`, `ldap`, ...).
    pub protocol: Option<String>,
    /// Source port on `host`.
    pub port: Option<u16>,
    /// AD domain of the principal, when known.
    pub domain: Option<String>,
    /// Secret kind matching rnxc's attempt log (`password` | `hash` | `null`).
    pub secret_kind: Option<String>,
    /// Structured extra metadata.
    pub metadata: Option<Value>,
}

/// Response body for `POST /credentials`.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub(super) struct CreatedCredential {
    id: i64,
    agent_id: String,
    name: String,
    captured_at: String,
}

/// Reserved agent id for credentials ingested from external tooling via the
/// REST API instead of captured from a live agent callback.  Registered as a
/// synthetic, always-active agent row so the `ts_loot` foreign key holds and
/// the records show up in the normal agent/credential listings.
pub(super) const IMPORT_AGENT_ID: u32 = 0x524E_5843; // "RNXC"
pub(super) const IMPORT_AGENT_LISTENER: &str = "import";

async fn ensure_import_agent(state: &TeamserverState) -> Result<(), CredentialApiError> {
    if state.database.agents().exists(IMPORT_AGENT_ID).await? {
        return Ok(());
    }
    let record = red_cell_common::AgentRecord {
        agent_id: IMPORT_AGENT_ID,
        active: true,
        reason: "import".to_owned(),
        note: "synthetic agent row for REST-API credential ingest".to_owned(),
        encryption: red_cell_common::AgentEncryptionInfo {
            aes_key: zeroize::Zeroizing::new(vec![0u8; 32]),
            aes_iv: zeroize::Zeroizing::new(vec![0u8; 16]),
            monotonic_ctr: false,
        },
        hostname: "external-tooling".to_owned(),
        username: "rnxc".to_owned(),
        domain_name: "IMPORT".to_owned(),
        external_ip: "0.0.0.0".to_owned(),
        internal_ip: "0.0.0.0".to_owned(),
        process_name: "rednetexec".to_owned(),
        process_path: String::new(),
        base_address: 0,
        process_pid: 0,
        process_tid: 0,
        process_ppid: 0,
        process_arch: "x64".to_owned(),
        elevated: false,
        os_version: "external".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 0,
        sleep_jitter: 0,
        kill_date: None,
        working_hours: None,
        first_call_in: String::new(),
        last_call_in: String::new(),
        archon_magic: None,
    };
    state
        .database
        .agents()
        .create_full(&record, IMPORT_AGENT_LISTENER, 0, false, false)
        .await?;
    Ok(())
}

// ── Error types ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub(super) enum LootApiError {
    #[error("{0}")]
    Teamserver(#[from] TeamserverError),
    #[error("{0}")]
    Authorization(#[from] AuthorizationError),
    #[error("invalid loot id `{value}`")]
    InvalidLootId { value: String },
    #[error("invalid agent id `{value}`")]
    InvalidAgentId { value: String },
    #[error("loot item `{id}` not found")]
    NotFound { id: i64 },
    #[error("loot item `{id}` does not contain downloadable data")]
    MissingData { id: i64 },
}

impl IntoResponse for LootApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Authorization(err) => err.into_response(),
            other => {
                let (status, code) = match &other {
                    Self::InvalidLootId { .. } => (StatusCode::BAD_REQUEST, "invalid_loot_id"),
                    Self::InvalidAgentId { .. } => (StatusCode::BAD_REQUEST, "invalid_agent_id"),
                    Self::NotFound { .. } => (StatusCode::NOT_FOUND, "loot_not_found"),
                    Self::MissingData { .. } => (StatusCode::CONFLICT, "loot_missing_data"),
                    Self::Teamserver(_) | Self::Authorization(_) => {
                        (StatusCode::INTERNAL_SERVER_ERROR, "loot_api_error")
                    }
                };
                json_error_response(status, code, other.to_string())
            }
        }
    }
}

#[derive(Debug, Error)]
pub(super) enum CredentialApiError {
    #[error("{0}")]
    Teamserver(#[from] TeamserverError),
    #[error("{0}")]
    Authorization(#[from] AuthorizationError),
    #[error("invalid credential id `{value}`")]
    InvalidCredentialId { value: String },
    #[error("invalid agent id `{value}`")]
    InvalidAgentId { value: String },
    #[error("credential `{id}` not found")]
    NotFound { id: i64 },
    #[error("invalid credential ingest: `{field}` must not be empty")]
    InvalidIngest { field: String },
}

impl IntoResponse for CredentialApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Authorization(err) => err.into_response(),
            other => {
                let (status, code) = match &other {
                    Self::InvalidCredentialId { .. } => {
                        (StatusCode::BAD_REQUEST, "invalid_credential_id")
                    }
                    Self::InvalidAgentId { .. } => (StatusCode::BAD_REQUEST, "invalid_agent_id"),
                    Self::NotFound { .. } => (StatusCode::NOT_FOUND, "credential_not_found"),
                    Self::InvalidIngest { .. } => (StatusCode::BAD_REQUEST, "invalid_credential_ingest"),
                    Self::Teamserver(_) | Self::Authorization(_) => {
                        (StatusCode::INTERNAL_SERVER_ERROR, "credential_api_error")
                    }
                };
                json_error_response(status, code, other.to_string())
            }
        }
    }
}

#[derive(Debug, Error)]
pub(super) enum JobApiError {
    #[error("{0}")]
    Teamserver(#[from] TeamserverError),
    #[error("{0}")]
    Authorization(#[from] AuthorizationError),
    #[error("invalid agent id `{value}`")]
    InvalidAgentId { value: String },
    #[error("invalid request id `{value}`")]
    InvalidRequestId { value: String },
    #[error("queued job not found for agent `{agent_id}` request `{request_id}`")]
    NotFound { agent_id: String, request_id: String },
}

impl IntoResponse for JobApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Authorization(err) => err.into_response(),
            other => {
                let (status, code) = match &other {
                    Self::InvalidAgentId { .. } => (StatusCode::BAD_REQUEST, "invalid_agent_id"),
                    Self::InvalidRequestId { .. } => {
                        (StatusCode::BAD_REQUEST, "invalid_request_id")
                    }
                    Self::NotFound { .. } => (StatusCode::NOT_FOUND, "job_not_found"),
                    Self::Teamserver(_) | Self::Authorization(_) => {
                        (StatusCode::INTERNAL_SERVER_ERROR, "job_api_error")
                    }
                };
                json_error_response(status, code, other.to_string())
            }
        }
    }
}

// ── Credential handlers ───────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/credentials",
    context_path = "/api/v1",
    tag = "credentials",
    security(("api_key" = [])),
    params(CredentialQuery),
    responses(
        (status = 200, description = "Filtered and paginated captured credentials", body = CredentialPage),
        (status = 400, description = "Invalid filter value", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
pub(super) async fn list_credentials(
    State(state): State<TeamserverState>,
    identity: ReadApiAccess,
    Query(query): Query<CredentialQuery>,
) -> Result<Json<CredentialPage>, CredentialApiError> {
    let offset = query.offset();
    let limit = query.limit();
    let filter = LootFilter {
        kind_exact: Some("credential".to_owned()),
        agent_id: parse_optional_agent_id(query.agent_id.as_deref(), |value| {
            CredentialApiError::InvalidAgentId { value }
        })?,
        name_contains: query.name.clone(),
        operator_contains: query.operator.clone(),
        command_contains: query.command.clone(),
        pattern_contains: query.pattern.clone(),
        since: normalize_timestamp_filter(query.since.as_deref()),
        until: normalize_timestamp_filter(query.until.as_deref()),
        ..LootFilter::default()
    };
    let repo = state.database.loot();
    // Hide credentials whose source agent is outside the operator's allow-list.
    // Pagination is applied after filtering so `total` reflects what the caller
    // can see, not what exists in the database; the row cap matches the
    // largest practical credential corpus while bounding memory.
    let unfiltered = repo.query_filtered(&filter, ACL_FILTER_ROW_CAP, 0).await?;
    let mut visible: Vec<CredentialSummary> = Vec::with_capacity(unfiltered.len());
    for record in unfiltered {
        if !operator_may_access_agent(&state, &identity.key_id, record.agent_id).await {
            continue;
        }
        if let Some(summary) = credential_summary(record) {
            visible.push(summary);
        }
    }
    let total = visible.len();
    let items = visible.into_iter().skip(offset).take(limit).collect();

    Ok(Json(CredentialPage { total, limit, offset, items }))
}

#[utoipa::path(
    get,
    path = "/credentials/{id}",
    context_path = "/api/v1",
    tag = "credentials",
    security(("api_key" = [])),
    params(("id" = String, Path, description = "Numeric credential identifier")),
    responses(
        (status = 200, description = "Captured credential details", body = CredentialSummary),
        (status = 400, description = "Invalid credential id", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Credential not found", body = ApiErrorBody)
    )
)]
pub(super) async fn get_credential(
    State(state): State<TeamserverState>,
    identity: ReadApiAccess,
    Path(id): Path<String>,
) -> Result<Json<CredentialSummary>, CredentialApiError> {
    let credential_id = id
        .trim()
        .parse::<i64>()
        .map_err(|_| CredentialApiError::InvalidCredentialId { value: id.clone() })?;
    let record = state
        .database
        .loot()
        .get(credential_id)
        .await?
        .filter(|record| record.kind.eq_ignore_ascii_case("credential"))
        .ok_or(CredentialApiError::NotFound { id: credential_id })?;
    authorize_agent_access(&state, &identity.key_id, record.agent_id).await?;

    credential_summary(record).map(Json).ok_or(CredentialApiError::NotFound { id: credential_id })
}


#[utoipa::path(
    post,
    path = "/credentials",
    context_path = "/api/v1",
    tag = "credentials",
    security(("api_key" = [])),
    request_body = CreateCredentialBody,
    responses(
        (status = 201, description = "Credential ingested", body = CreatedCredential),
        (status = 400, description = "Invalid request body", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
/// Ingest a credential validated by external tooling (e.g. RedNetExec `rnxc
/// c2feed`).  The record is stored as loot of kind `credential` attributed to
/// a synthetic import agent so it flows through the normal credential
/// inventory and audits.
pub(super) async fn create_credential(
    State(state): State<TeamserverState>,
    identity: TaskAgentApiAccess,
    Json(body): Json<CreateCredentialBody>,
) -> Result<(StatusCode, Json<CreatedCredential>), CredentialApiError> {
    if body.name.trim().is_empty() {
        return Err(CredentialApiError::InvalidIngest { field: "name".to_owned() });
    }
    if body.content.is_empty() {
        return Err(CredentialApiError::InvalidIngest { field: "content".to_owned() });
    }
    ensure_import_agent(&state).await?;

    let captured_at = now_rfc3339();
    let mut metadata = body.metadata.clone().unwrap_or_else(|| Value::Object(Default::default()));
    if let Some(object) = metadata.as_object_mut() {
        object.insert("operator".to_owned(), Value::String(identity.key_id.clone()));
        object.insert("tool".to_owned(), Value::String("rednetexec".to_owned()));
        for (key, value) in [
            ("host", body.host.clone().filter(|v| !v.is_empty()).map(Value::String)),
            ("protocol", body.protocol.clone().filter(|v| !v.is_empty()).map(Value::String)),
            ("port", body.port.map(|p| Value::Number(p.into()))),
            ("domain", body.domain.clone().filter(|v| !v.is_empty()).map(Value::String)),
            ("secret_kind", body.secret_kind.clone().filter(|v| !v.is_empty()).map(Value::String)),
        ] {
            if let Some(value) = value {
                object.entry(key).or_insert(value);
            }
        }
    }

    let record = LootRecord {
        id: None,
        agent_id: IMPORT_AGENT_ID,
        kind: "credential".to_owned(),
        name: body.name.trim().to_owned(),
        file_path: None,
        size_bytes: Some(i64::try_from(body.content.len()).unwrap_or(i64::MAX)),
        captured_at: captured_at.clone(),
        data: Some(body.content.into_bytes()),
        metadata: Some(metadata),
    };
    let id = state.database.loot().create(&record).await?;

    record_audit_entry(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        "credential.ingest",
        "credential",
        Some(id.to_string()),
        crate::audit_details(
            AuditResultStatus::Success,
            Some(IMPORT_AGENT_ID),
            Some("ingest"),
            Some(parameter_object([
                ("name", Value::String(record.name.clone())),
                ("size_bytes", Value::Number(record.size_bytes.unwrap_or(0).into())),
            ])),
        ),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(CreatedCredential {
            id,
            agent_id: format!("{IMPORT_AGENT_ID:08X}"),
            name: record.name,
            captured_at,
        }),
    ))
}

// ── Job handlers ──────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/jobs",
    context_path = "/api/v1",
    tag = "jobs",
    security(("api_key" = [])),
    params(JobQuery),
    responses(
        (status = 200, description = "Queued jobs across all tracked agents", body = JobPage),
        (status = 400, description = "Invalid filter value", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
pub(super) async fn list_jobs(
    State(state): State<TeamserverState>,
    identity: ReadApiAccess,
    Query(query): Query<JobQuery>,
) -> Result<Json<JobPage>, JobApiError> {
    let normalized_agent_id = normalize_agent_filter(query.agent_id.as_deref(), |value| {
        JobApiError::InvalidAgentId { value }
    })?;
    let normalized_request_id = normalize_request_filter(query.request_id.as_deref(), |value| {
        JobApiError::InvalidRequestId { value }
    })?;

    let raw: Vec<QueuedJob> = state
        .agent_registry
        .queued_jobs_all()
        .await
        .into_iter()
        .filter(|queued_job| {
            job_matches(
                &query,
                queued_job,
                normalized_agent_id.as_deref(),
                normalized_request_id.as_deref(),
            )
        })
        .collect();

    // Skip jobs whose agent is outside the operator's allow-list before
    // paginating so `total` reflects what the caller can see.
    let mut items: Vec<JobSummary> = Vec::with_capacity(raw.len());
    for queued_job in raw {
        if !operator_may_access_agent(&state, &identity.key_id, queued_job.agent_id).await {
            continue;
        }
        items.push(job_summary(queued_job));
    }

    let total = items.len();
    let offset = query.offset();
    let limit = query.limit();
    items = items.into_iter().skip(offset).take(limit).collect();

    Ok(Json(JobPage { total, limit, offset, items }))
}

#[utoipa::path(
    get,
    path = "/jobs/{agent_id}/{request_id}",
    context_path = "/api/v1",
    tag = "jobs",
    security(("api_key" = [])),
    params(
        ("agent_id" = String, Path, description = "Agent id in hex (with optional 0x prefix)"),
        ("request_id" = String, Path, description = "Request id in hex (with optional 0x prefix)")
    ),
    responses(
        (status = 200, description = "Queued job details", body = JobSummary),
        (status = 400, description = "Invalid identifier", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Queued job not found", body = ApiErrorBody)
    )
)]
pub(super) async fn get_job(
    State(state): State<TeamserverState>,
    identity: ReadApiAccess,
    Path((agent_id, request_id)): Path<(String, String)>,
) -> Result<Json<JobSummary>, JobApiError> {
    let normalized_agent_id = normalize_agent_filter(Some(agent_id.as_str()), |value| {
        JobApiError::InvalidAgentId { value }
    })?
    .ok_or(JobApiError::InvalidAgentId { value: agent_id.clone() })?;
    let normalized_request_id = normalize_request_filter(Some(request_id.as_str()), |value| {
        JobApiError::InvalidRequestId { value }
    })?
    .ok_or(JobApiError::InvalidRequestId { value: request_id.clone() })?;

    let queued_job = state
        .agent_registry
        .queued_jobs_all()
        .await
        .into_iter()
        .find(|queued_job| {
            format!("{:08X}", queued_job.agent_id) == normalized_agent_id
                && format!("{:X}", queued_job.job.request_id) == normalized_request_id
        })
        .ok_or(JobApiError::NotFound {
            agent_id: normalized_agent_id.clone(),
            request_id: normalized_request_id.clone(),
        })?;

    authorize_agent_access(&state, &identity.key_id, queued_job.agent_id).await?;
    Ok(Json(job_summary(queued_job)))
}

// ── Loot handlers ─────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/loot",
    context_path = "/api/v1",
    tag = "loot",
    security(("api_key" = [])),
    params(LootQuery),
    responses(
        (status = 200, description = "Filtered and paginated captured loot", body = LootPage),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
pub(super) async fn list_loot(
    State(state): State<TeamserverState>,
    identity: ReadApiAccess,
    Query(query): Query<LootQuery>,
) -> Result<Json<LootPage>, LootApiError> {
    let offset = query.offset();
    let limit = query.limit();
    let filter = LootFilter {
        kind_contains: query.kind.clone(),
        agent_id: parse_optional_agent_id(query.agent_id.as_deref(), |value| {
            LootApiError::InvalidAgentId { value }
        })?,
        name_contains: query.name.clone(),
        file_path_contains: query.file_path.clone(),
        operator_contains: query.operator.clone(),
        command_contains: query.command.clone(),
        since: normalize_timestamp_filter(query.since.as_deref()),
        until: normalize_timestamp_filter(query.until.as_deref()),
        ..LootFilter::default()
    };
    let repo = state.database.loot();
    // Hide loot whose source agent is outside the operator's allow-list.
    // Pagination is applied after filtering so `total` reflects what the
    // caller can see, not the raw row count.
    let unfiltered = repo.query_filtered(&filter, ACL_FILTER_ROW_CAP, 0).await?;
    let mut visible: Vec<LootSummary> = Vec::with_capacity(unfiltered.len());
    for record in unfiltered {
        if !operator_may_access_agent(&state, &identity.key_id, record.agent_id).await {
            continue;
        }
        visible.push(loot_summary(record));
    }
    let total = visible.len();
    let items = visible.into_iter().skip(offset).take(limit).collect();

    Ok(Json(LootPage { total, limit, offset, items }))
}

#[utoipa::path(
    get,
    path = "/loot/{id}",
    context_path = "/api/v1",
    tag = "loot",
    security(("api_key" = [])),
    params(("id" = String, Path, description = "Numeric loot identifier")),
    responses(
        (status = 200, description = "Loot item binary content"),
        (status = 400, description = "Invalid loot id", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Loot item not found", body = ApiErrorBody),
        (status = 409, description = "Loot item has no stored binary content", body = ApiErrorBody)
    )
)]
pub(super) async fn get_loot(
    State(state): State<TeamserverState>,
    identity: ReadApiAccess,
    Path(id): Path<String>,
) -> Result<Response, LootApiError> {
    let loot_id =
        id.parse::<i64>().map_err(|_| LootApiError::InvalidLootId { value: id.clone() })?;
    let record =
        state.database.loot().get(loot_id).await?.ok_or(LootApiError::NotFound { id: loot_id })?;
    authorize_agent_access(&state, &identity.key_id, record.agent_id).await?;
    let data = record.data.ok_or(LootApiError::MissingData { id: loot_id })?;
    let filename = sanitize_filename(record.name.as_str());
    let content_type = loot_content_type(record.kind.as_str(), filename.as_str());

    let mut response = Response::new(axum::body::Body::from(data));
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        content_type.parse().map_err(|error: axum::http::header::InvalidHeaderValue| {
            LootApiError::Teamserver(TeamserverError::InvalidPersistedValue {
                field: "content_type",
                message: error.to_string(),
            })
        })?,
    );
    headers.insert(
        CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"").parse().map_err(
            |error: axum::http::header::InvalidHeaderValue| {
                LootApiError::Teamserver(TeamserverError::InvalidPersistedValue {
                    field: "content_disposition",
                    message: error.to_string(),
                })
            },
        )?,
    );

    Ok(response)
}

// ── Private helper functions ──────────────────────────────────────────────────

fn loot_summary(record: LootRecord) -> LootSummary {
    let (operator, command_line, task_id) = loot_context_fields(record.metadata.as_ref());
    LootSummary {
        id: record.id.unwrap_or_default(),
        agent_id: format!("{:08X}", record.agent_id),
        kind: record.kind,
        name: record.name,
        file_path: record.file_path,
        size_bytes: record.size_bytes,
        captured_at: record.captured_at,
        has_data: record.data.is_some(),
        operator,
        command_line,
        task_id,
        metadata: record.metadata,
    }
}

fn credential_summary(record: LootRecord) -> Option<CredentialSummary> {
    if !record.kind.eq_ignore_ascii_case("credential") {
        return None;
    }

    let (operator, command_line, task_id) = loot_context_fields(record.metadata.as_ref());
    Some(CredentialSummary {
        id: record.id.unwrap_or_default(),
        agent_id: format!("{:08X}", record.agent_id),
        name: record.name,
        captured_at: record.captured_at,
        operator,
        command_line,
        task_id,
        pattern: metadata_string_field(record.metadata.as_ref(), "pattern"),
        content: record.data.as_deref().map(|data| String::from_utf8_lossy(data).into_owned()),
        metadata: record.metadata,
    })
}

fn job_summary(queued_job: QueuedJob) -> JobSummary {
    JobSummary {
        agent_id: format!("{:08X}", queued_job.agent_id),
        command_id: queued_job.job.command,
        request_id: format!("{:X}", queued_job.job.request_id),
        task_id: queued_job.job.task_id,
        command_line: queued_job.job.command_line,
        created_at: queued_job.job.created_at,
        operator: (!queued_job.job.operator.is_empty()).then_some(queued_job.job.operator),
        payload_size: queued_job.job.payload.len(),
    }
}

fn normalize_agent_filter<E>(
    value: Option<&str>,
    invalid: impl FnOnce(String) -> E + Copy,
) -> Result<Option<String>, E> {
    value
        .map(|filter_value| match parse_hex_u32(filter_value) {
            Some(parsed) => Ok(format!("{parsed:08X}")),
            None => Err(invalid(filter_value.to_owned())),
        })
        .transpose()
}

fn normalize_request_filter<E>(
    value: Option<&str>,
    invalid: impl FnOnce(String) -> E + Copy,
) -> Result<Option<String>, E> {
    value
        .map(|filter_value| match parse_hex_u32(filter_value) {
            Some(parsed) => Ok(format!("{parsed:X}")),
            None => Err(invalid(filter_value.to_owned())),
        })
        .transpose()
}

fn job_matches(
    query: &JobQuery,
    queued_job: &QueuedJob,
    normalized_agent_id: Option<&str>,
    normalized_request_id: Option<&str>,
) -> bool {
    normalized_agent_id.is_none_or(|agent_id| format!("{:08X}", queued_job.agent_id) == agent_id)
        && normalized_request_id
            .is_none_or(|request_id| format!("{:X}", queued_job.job.request_id) == request_id)
        && query.command_id.is_none_or(|command_id| queued_job.job.command == command_id)
        && contains_filter(queued_job.job.command_line.as_str(), query.command.as_deref())
        && contains_filter(queued_job.job.task_id.as_str(), query.task_id.as_deref())
        && optional_contains_filter(
            (!queued_job.job.operator.is_empty()).then_some(queued_job.job.operator.as_str()),
            query.operator.as_deref(),
        )
}

fn loot_context_fields(
    metadata: Option<&Value>,
) -> (Option<String>, Option<String>, Option<String>) {
    let object = metadata.and_then(Value::as_object);
    let operator = object
        .and_then(|value| value.get("operator"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let command_line = object
        .and_then(|value| value.get("command_line"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let task_id = object
        .and_then(|value| value.get("task_id"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    (operator, command_line, task_id)
}

fn metadata_string_field(metadata: Option<&Value>, key: &str) -> Option<String> {
    metadata
        .and_then(Value::as_object)
        .and_then(|value| value.get(key))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn parse_rfc3339(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

fn normalize_timestamp_filter(value: Option<&str>) -> Option<String> {
    parse_rfc3339(value?)
        .and_then(|timestamp| timestamp.to_offset(time::UtcOffset::UTC).format(&Rfc3339).ok())
}

fn parse_optional_agent_id<E>(
    value: Option<&str>,
    invalid: impl FnOnce(String) -> E + Copy,
) -> Result<Option<u32>, E> {
    value
        .map(|filter_value| {
            parse_hex_u32(filter_value).ok_or_else(|| invalid(filter_value.to_owned()))
        })
        .transpose()
}

fn parse_hex_u32(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let hex_digits =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    u32::from_str_radix(hex_digits, 16).ok()
}

fn contains_filter(value: &str, filter: Option<&str>) -> bool {
    filter.is_none_or(|filter| value.contains(filter))
}

fn optional_contains_filter(value: Option<&str>, filter: Option<&str>) -> bool {
    filter.is_none_or(|filter| value.is_some_and(|value| value.contains(filter)))
}

fn sanitize_filename(filename: &str) -> String {
    let sanitized = filename.replace(['"', '\n', '\r'], "_");
    if sanitized.is_empty() { "loot.bin".to_owned() } else { sanitized }
}

fn loot_content_type(kind: &str, filename: &str) -> &'static str {
    if kind.eq_ignore_ascii_case("screenshot") || filename.ends_with(".png") {
        "image/png"
    } else if kind.eq_ignore_ascii_case("credential") || filename.ends_with(".txt") {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}
