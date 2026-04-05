//! `red-cell-cli listener` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `listener list` | `GET /listeners` | table of all listeners |
//! | `listener show <name>` | `GET /listeners/{name}` | full listener record |
//! | `listener create` | `POST /listeners` | creates with flag-built or raw-JSON config |
//! | `listener start <name>` | `PUT /listeners/{name}/start` | idempotent |
//! | `listener stop <name>` | `PUT /listeners/{name}/stop` | idempotent |
//! | `listener delete <name>` | `DELETE /listeners/{name}` | hard delete |
//! | `listener access <name>` | `GET /listeners/{name}/access` | operator allow-list |
//! | `listener set-access <name>` | `PUT /listeners/{name}/access` | replace allow-list |

use red_cell_common::{
    DnsListenerConfig, ExternalListenerConfig, HttpListenerConfig, SmbListenerConfig,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::ListenerCommands;
use crate::client::ApiClient;
use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{OutputFormat, TextRender, TextRow, print_error, print_success};

// ── raw API response shapes ───────────────────────────────────────────────────

/// Raw `ListenerSummary` returned by the teamserver.
///
/// Uses `serde_json::Value` for `config` because the nested tagged-enum shape
/// (`{"protocol":"http","config":{...}}`) is complex to replicate locally.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct RawListenerSummary {
    pub(crate) name: String,
    pub(crate) protocol: String,
    pub(crate) state: RawListenerState,
    pub(crate) config: serde_json::Value,
}

/// Raw listener runtime state from the server.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct RawListenerState {
    pub(crate) status: String,
    pub(crate) last_error: Option<String>,
}

// ── public output types ───────────────────────────────────────────────────────

/// Summary row returned by `listener list`.
#[derive(Debug, Clone, Serialize)]
pub struct ListenerRow {
    /// Listener display name.
    pub name: String,
    /// Protocol family: `"http"`, `"dns"`, `"smb"`, or `"external"`.
    pub protocol: String,
    /// Lifecycle status: `"Running"`, `"Stopped"`, `"Created"`, `"Error"`.
    pub status: String,
    /// Short protocol-specific summary (port, pipe name, domain, etc.).
    pub info: String,
}

impl TextRow for ListenerRow {
    fn headers() -> Vec<&'static str> {
        vec!["Name", "Protocol", "Status", "Info"]
    }

    fn row(&self) -> Vec<String> {
        vec![self.name.clone(), self.protocol.clone(), self.status.clone(), self.info.clone()]
    }
}

/// Full listener detail returned by `listener show` and `listener create`.
#[derive(Debug, Clone, Serialize)]
pub struct ListenerDetail {
    /// Listener display name.
    pub name: String,
    /// Protocol family.
    pub protocol: String,
    /// Lifecycle status.
    pub status: String,
    /// Most recent start failure, if any.
    pub last_error: Option<String>,
    /// Full configuration object (protocol-specific shape).
    pub config: serde_json::Value,
}

impl TextRender for ListenerDetail {
    fn render_text(&self) -> String {
        use comfy_table::{Cell, ContentArrangement, Table};
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header([Cell::new("Field"), Cell::new("Value")]);
        let rows: &[(&str, String)] = &[
            ("name", self.name.clone()),
            ("protocol", self.protocol.clone()),
            ("status", self.status.clone()),
            ("last_error", self.last_error.clone().unwrap_or_default()),
            ("config", serde_json::to_string_pretty(&self.config).unwrap_or_default()),
        ];
        for (field, val) in rows {
            table.add_row([Cell::new(*field), Cell::new(val)]);
        }
        table.to_string()
    }
}

/// Result of `listener start` / `listener stop`.
#[derive(Debug, Clone, Serialize)]
pub struct ListenerActionResult {
    /// Listener display name.
    pub name: String,
    /// Current lifecycle status after the operation.
    pub status: String,
    /// `true` when the listener was already in the target state (idempotent).
    pub already_in_state: bool,
}

impl TextRender for ListenerActionResult {
    fn render_text(&self) -> String {
        if self.already_in_state {
            format!("Listener {} — already {}", self.name, self.status)
        } else {
            format!("Listener {} — {}", self.name, self.status)
        }
    }
}

/// Result of `listener delete`.
#[derive(Debug, Clone, Serialize)]
pub struct ListenerDeleted {
    /// Name of the deleted listener.
    pub name: String,
    /// Always `true`.
    pub deleted: bool,
}

impl TextRender for ListenerDeleted {
    fn render_text(&self) -> String {
        format!("Listener {} deleted", self.name)
    }
}

/// Wire body for `GET`/`PUT /listeners/{name}/access`.
#[derive(Debug, Deserialize)]
struct RawListenerAccessResponse {
    listener_name: String,
    allowed_operators: Vec<String>,
}

/// Operator allow-list for a listener (`listener access` / `listener set-access`).
#[derive(Debug, Clone, Serialize)]
pub struct ListenerAccessInfo {
    /// Listener name.
    pub listener_name: String,
    /// Operators allowed to use this listener (empty means unrestricted).
    pub allowed_operators: Vec<String>,
}

impl TextRender for ListenerAccessInfo {
    fn render_text(&self) -> String {
        if self.allowed_operators.is_empty() {
            format!("Listener {} — no operator restrictions.", self.listener_name)
        } else {
            format!(
                "Listener {} — allowed operators: {}",
                self.listener_name,
                self.allowed_operators.join(", ")
            )
        }
    }
}

// ── top-level dispatcher ──────────────────────────────────────────────────────

/// Dispatch a [`ListenerCommands`] variant and return a process exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: ListenerCommands) -> i32 {
    match action {
        ListenerCommands::List => match list(client).await {
            Ok(data) => match print_success(fmt, &data) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },

        ListenerCommands::Show { name } => match show(client, &name).await {
            Ok(data) => match print_success(fmt, &data) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },

        ListenerCommands::Create {
            name,
            listener_type,
            port,
            host,
            domain,
            pipe_name,
            endpoint,
            secure,
            config_json,
        } => {
            match create(
                client,
                &name,
                &listener_type,
                port,
                &host,
                domain.as_deref(),
                pipe_name.as_deref(),
                endpoint.as_deref(),
                secure,
                config_json.as_deref(),
            )
            .await
            {
                Ok(data) => match print_success(fmt, &data) {
                    Ok(()) => EXIT_SUCCESS,
                    Err(e) => {
                        print_error(&e).ok();
                        e.exit_code()
                    }
                },
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }

        ListenerCommands::Start { name } => match start(client, &name).await {
            Ok(data) => match print_success(fmt, &data) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },

        ListenerCommands::Stop { name } => match stop(client, &name).await {
            Ok(data) => match print_success(fmt, &data) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },

        ListenerCommands::Delete { name } => match delete(client, &name).await {
            Ok(data) => match print_success(fmt, &data) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },

        ListenerCommands::Access { name } => match get_access(client, &name).await {
            Ok(data) => match print_success(fmt, &data) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },

        ListenerCommands::SetAccess { name, allow_operator } => {
            match set_access(client, &name, &allow_operator).await {
                Ok(data) => match print_success(fmt, &data) {
                    Ok(()) => EXIT_SUCCESS,
                    Err(e) => {
                        print_error(&e).ok();
                        e.exit_code()
                    }
                },
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }
    }
}

// ── command implementations ───────────────────────────────────────────────────

/// `listener list` — fetch all configured listeners.
///
/// # Examples
/// ```text
/// red-cell-cli listener list
/// ```
#[instrument(skip(client))]
async fn list(client: &ApiClient) -> Result<Vec<ListenerRow>, CliError> {
    let raw: Vec<RawListenerSummary> = client.get("/listeners").await?;
    Ok(raw.into_iter().map(listener_row_from_raw).collect())
}

/// `listener show <name>` — fetch full details of a single listener.
///
/// # Examples
/// ```text
/// red-cell-cli listener show http1
/// ```
#[instrument(skip(client))]
async fn show(client: &ApiClient, name: &str) -> Result<ListenerDetail, CliError> {
    let raw: RawListenerSummary = client.get(&format!("/listeners/{name}")).await?;
    Ok(listener_detail_from_raw(raw))
}

/// `listener create` — create a new listener from flags or raw JSON.
///
/// When `config_json` is supplied it is used as the inner config body and all
/// other per-type flags are ignored.  Otherwise a minimal config is assembled
/// from the flag values and sensible defaults.
///
/// # Examples
/// ```text
/// red-cell-cli listener create --name http1 --type http --port 443
/// red-cell-cli listener create --name dns1  --type dns  --domain c2.example.com
/// red-cell-cli listener create --name smb1  --type smb  --pipe-name my-pipe
/// red-cell-cli listener create --name ext1  --type external --endpoint /bridge
/// ```
#[allow(clippy::too_many_arguments)]
#[instrument(skip(client))]
async fn create(
    client: &ApiClient,
    name: &str,
    listener_type: &str,
    port: Option<u16>,
    host: &str,
    domain: Option<&str>,
    pipe_name: Option<&str>,
    endpoint: Option<&str>,
    secure: bool,
    config_json: Option<&str>,
) -> Result<ListenerDetail, CliError> {
    let body = build_create_body(
        name,
        listener_type,
        port,
        host,
        domain,
        pipe_name,
        endpoint,
        secure,
        config_json,
    )?;
    let raw: RawListenerSummary = client.post("/listeners", &body).await?;
    Ok(listener_detail_from_raw(raw))
}

/// `listener start <name>` — start a stopped listener.
///
/// Idempotent: if the listener is already running the current state is
/// returned with `already_in_state: true`.
///
/// # Examples
/// ```text
/// red-cell-cli listener start http1
/// ```
#[instrument(skip(client))]
async fn start(client: &ApiClient, name: &str) -> Result<ListenerActionResult, CliError> {
    match client.put_empty::<RawListenerSummary>(&format!("/listeners/{name}/start")).await {
        Ok(raw) => Ok(ListenerActionResult {
            name: name.to_owned(),
            status: raw.state.status,
            already_in_state: false,
        }),
        Err(CliError::General(msg)) if msg.contains("listener_already_running") => {
            // Idempotent path: fetch the current state and return it.
            let raw: RawListenerSummary = client.get(&format!("/listeners/{name}")).await?;
            Ok(ListenerActionResult {
                name: name.to_owned(),
                status: raw.state.status,
                already_in_state: true,
            })
        }
        Err(e) => Err(e),
    }
}

/// `listener stop <name>` — stop a running listener.
///
/// Idempotent: if the listener is already stopped the current state is
/// returned with `already_in_state: true`.
///
/// # Examples
/// ```text
/// red-cell-cli listener stop http1
/// ```
#[instrument(skip(client))]
async fn stop(client: &ApiClient, name: &str) -> Result<ListenerActionResult, CliError> {
    match client.put_empty::<RawListenerSummary>(&format!("/listeners/{name}/stop")).await {
        Ok(raw) => Ok(ListenerActionResult {
            name: name.to_owned(),
            status: raw.state.status,
            already_in_state: false,
        }),
        Err(CliError::General(msg)) if msg.contains("listener_not_running") => {
            let raw: RawListenerSummary = client.get(&format!("/listeners/{name}")).await?;
            Ok(ListenerActionResult {
                name: name.to_owned(),
                status: raw.state.status,
                already_in_state: true,
            })
        }
        Err(e) => Err(e),
    }
}

/// `listener delete <name>` — permanently delete a listener.
///
/// # Examples
/// ```text
/// red-cell-cli listener delete http1
/// ```
#[instrument(skip(client))]
async fn delete(client: &ApiClient, name: &str) -> Result<ListenerDeleted, CliError> {
    client.delete_no_body(&format!("/listeners/{name}")).await?;
    Ok(ListenerDeleted { name: name.to_owned(), deleted: true })
}

/// `listener access <name>` — fetch the operator allow-list for a listener.
///
/// # Examples
/// ```text
/// red-cell-cli listener access http1
/// ```
#[instrument(skip(client))]
async fn get_access(client: &ApiClient, name: &str) -> Result<ListenerAccessInfo, CliError> {
    let raw: RawListenerAccessResponse = client.get(&format!("/listeners/{name}/access")).await?;
    Ok(ListenerAccessInfo {
        listener_name: raw.listener_name,
        allowed_operators: raw.allowed_operators,
    })
}

/// `listener set-access <name>` — replace the operator allow-list.
///
/// # Examples
/// ```text
/// red-cell-cli listener set-access http1 --allow-operator alice
/// red-cell-cli listener set-access http1
/// ```
#[instrument(skip(client, operators))]
async fn set_access(
    client: &ApiClient,
    name: &str,
    operators: &[String],
) -> Result<ListenerAccessInfo, CliError> {
    let body = serde_json::json!({ "allowed_operators": operators });
    let raw: RawListenerAccessResponse =
        client.put(&format!("/listeners/{name}/access"), &body).await?;
    Ok(ListenerAccessInfo {
        listener_name: raw.listener_name,
        allowed_operators: raw.allowed_operators,
    })
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build the `POST /listeners` request body from CLI flags or raw JSON.
///
/// The server expects a tagged-enum envelope:
/// ```json
/// {"protocol": "http", "config": { <inner config fields> }}
/// ```
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_create_body(
    name: &str,
    listener_type: &str,
    port: Option<u16>,
    host: &str,
    domain: Option<&str>,
    pipe_name: Option<&str>,
    endpoint: Option<&str>,
    secure: bool,
    config_json: Option<&str>,
) -> Result<serde_json::Value, CliError> {
    // Normalise the protocol tag to lowercase.
    let protocol = listener_type.to_lowercase();
    let protocol = match protocol.as_str() {
        "https" => "http",
        other => other,
    };

    // If the caller provided raw inner-config JSON, wrap it in the envelope
    // and return immediately.
    if let Some(raw_json) = config_json {
        let inner: serde_json::Value = serde_json::from_str(raw_json)
            .map_err(|e| CliError::InvalidArgs(format!("--config-json is not valid JSON: {e}")))?;
        validate_inner_config_json_for_protocol(protocol, &inner)?;
        return Ok(serde_json::json!({
            "protocol": protocol,
            "config": inner,
        }));
    }

    // Build a minimal inner config from flags.
    let inner: serde_json::Value = match protocol {
        "http" => {
            let port_bind = port.unwrap_or(443);
            serde_json::json!({
                "name": name,
                "host_bind": host,
                "port_bind": port_bind,
                "host_rotation": "round-robin",
                "secure": secure,
            })
        }
        "dns" => {
            let dom = domain.ok_or_else(|| {
                CliError::InvalidArgs("--domain is required for --type dns".to_owned())
            })?;
            let port_bind = port.unwrap_or(53);
            serde_json::json!({
                "name": name,
                "host_bind": host,
                "port_bind": port_bind,
                "domain": dom,
            })
        }
        "smb" => {
            let pipe = pipe_name.ok_or_else(|| {
                CliError::InvalidArgs("--pipe-name is required for --type smb".to_owned())
            })?;
            serde_json::json!({
                "name": name,
                "pipe_name": pipe,
            })
        }
        "external" => {
            let ep = endpoint.ok_or_else(|| {
                CliError::InvalidArgs("--endpoint is required for --type external".to_owned())
            })?;
            serde_json::json!({
                "name": name,
                "endpoint": ep,
            })
        }
        other => {
            return Err(CliError::InvalidArgs(format!(
                "unknown listener type '{other}': expected http, dns, smb, or external"
            )));
        }
    };

    Ok(serde_json::json!({
        "protocol": protocol,
        "config": inner,
    }))
}

/// Best-effort check that `--config-json` matches the schema for `--type` /
/// `--protocol` before sending `POST /listeners`.
///
/// Protocols recognised here use the canonical structs from `red_cell_common`.
/// Any other protocol string is left to the teamserver so future listener types
/// are not blocked by an older CLI.
fn validate_inner_config_json_for_protocol(
    protocol: &str,
    inner: &serde_json::Value,
) -> Result<(), CliError> {
    match protocol {
        "http" => serde_json::from_value::<HttpListenerConfig>(inner.clone())
            .map_err(|e| {
                CliError::InvalidArgs(format!(
                    "--config-json does not match HTTP listener schema: {e}"
                ))
            })
            .map(|_| ()),
        "dns" => serde_json::from_value::<DnsListenerConfig>(inner.clone())
            .map_err(|e| {
                CliError::InvalidArgs(format!(
                    "--config-json does not match DNS listener schema: {e}"
                ))
            })
            .map(|_| ()),
        "smb" => serde_json::from_value::<SmbListenerConfig>(inner.clone())
            .map_err(|e| {
                CliError::InvalidArgs(format!(
                    "--config-json does not match SMB listener schema: {e}"
                ))
            })
            .map(|_| ()),
        "external" => serde_json::from_value::<ExternalListenerConfig>(inner.clone())
            .map_err(|e| {
                CliError::InvalidArgs(format!(
                    "--config-json does not match external listener schema: {e}"
                ))
            })
            .map(|_| ()),
        _ => Ok(()),
    }
}

/// Extract a short info string from the raw `ListenerSummary.config` value.
///
/// The config value is the tagged-enum payload:
/// `{"protocol":"http","config":{"port_bind":443,...}}`.
fn extract_info(raw: &RawListenerSummary) -> String {
    // The server-side ListenerConfig is serialised as a tagged enum:
    // { "protocol": "<proto>", "config": { <inner fields> } }
    let inner = raw.config.get("config");

    match raw.protocol.as_str() {
        "http" => {
            let port = inner
                .and_then(|c| c.get("port_bind"))
                .and_then(serde_json::Value::as_u64)
                .map_or_else(|| "?".to_owned(), |p| p.to_string());
            let host = inner
                .and_then(|c| c.get("host_bind"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let secure = inner
                .and_then(|c| c.get("secure"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let scheme = if secure { "https" } else { "http" };
            format!("{scheme}://{host}:{port}")
        }
        "dns" => {
            let domain = inner
                .and_then(|c| c.get("domain"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let port = inner
                .and_then(|c| c.get("port_bind"))
                .and_then(serde_json::Value::as_u64)
                .map_or_else(|| "53".to_owned(), |p| p.to_string());
            format!("domain={domain} port={port}")
        }
        "smb" => {
            let pipe = inner
                .and_then(|c| c.get("pipe_name"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            format!("pipe={pipe}")
        }
        "external" => {
            let ep = inner
                .and_then(|c| c.get("endpoint"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            format!("endpoint={ep}")
        }
        _ => String::new(),
    }
}

fn listener_row_from_raw(raw: RawListenerSummary) -> ListenerRow {
    let info = extract_info(&raw);
    ListenerRow { name: raw.name, protocol: raw.protocol, status: raw.state.status, info }
}

fn listener_detail_from_raw(raw: RawListenerSummary) -> ListenerDetail {
    ListenerDetail {
        name: raw.name,
        protocol: raw.protocol,
        status: raw.state.status,
        last_error: raw.state.last_error,
        config: raw.config,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ListenerRow ───────────────────────────────────────────────────────────

    #[test]
    fn listener_row_headers_match_row_length() {
        let row = ListenerRow {
            name: "http1".to_owned(),
            protocol: "http".to_owned(),
            status: "Running".to_owned(),
            info: "http://0.0.0.0:443".to_owned(),
        };
        assert_eq!(ListenerRow::headers().len(), row.row().len());
    }

    #[test]
    fn listener_row_serialises_all_fields() {
        let row = ListenerRow {
            name: "dns1".to_owned(),
            protocol: "dns".to_owned(),
            status: "Stopped".to_owned(),
            info: "domain=c2.evil.example port=53".to_owned(),
        };
        let v = serde_json::to_value(&row).expect("serialise");
        assert_eq!(v["name"], "dns1");
        assert_eq!(v["protocol"], "dns");
        assert_eq!(v["status"], "Stopped");
    }

    #[test]
    fn vec_listener_row_renders_table() {
        let rows = vec![ListenerRow {
            name: "http1".to_owned(),
            protocol: "http".to_owned(),
            status: "Running".to_owned(),
            info: "https://0.0.0.0:443".to_owned(),
        }];
        let rendered = rows.render_text();
        assert!(rendered.contains("http1"));
        assert!(rendered.contains("Running"));
    }

    // ── ListenerDetail ────────────────────────────────────────────────────────

    #[test]
    fn listener_detail_serialises_config_as_json_value() {
        let detail = ListenerDetail {
            name: "smb1".to_owned(),
            protocol: "smb".to_owned(),
            status: "Created".to_owned(),
            last_error: None,
            config: serde_json::json!({"protocol":"smb","config":{"name":"smb1","pipe_name":"my-pipe"}}),
        };
        let v = serde_json::to_value(&detail).expect("serialise");
        assert_eq!(v["name"], "smb1");
        assert_eq!(v["protocol"], "smb");
        assert!(v["last_error"].is_null());
    }

    #[test]
    fn listener_detail_render_text_contains_key_fields() {
        let detail = ListenerDetail {
            name: "http1".to_owned(),
            protocol: "http".to_owned(),
            status: "Running".to_owned(),
            last_error: None,
            config: serde_json::json!({"protocol":"http","config":{"port_bind":443}}),
        };
        let rendered = detail.render_text();
        assert!(rendered.contains("http1"));
        assert!(rendered.contains("Running"));
    }

    // ── ListenerActionResult ──────────────────────────────────────────────────

    #[test]
    fn listener_action_result_render_text_normal() {
        let r = ListenerActionResult {
            name: "http1".to_owned(),
            status: "Running".to_owned(),
            already_in_state: false,
        };
        assert!(r.render_text().contains("http1"));
        assert!(r.render_text().contains("Running"));
        assert!(!r.render_text().contains("already"));
    }

    #[test]
    fn listener_action_result_render_text_idempotent() {
        let r = ListenerActionResult {
            name: "http1".to_owned(),
            status: "Running".to_owned(),
            already_in_state: true,
        };
        assert!(r.render_text().contains("already"));
    }

    #[test]
    fn listener_action_result_serialises_already_in_state_field() {
        let r = ListenerActionResult {
            name: "x".to_owned(),
            status: "Stopped".to_owned(),
            already_in_state: true,
        };
        let v = serde_json::to_value(&r).expect("serialise");
        assert_eq!(v["already_in_state"], true);
    }

    // ── ListenerDeleted ───────────────────────────────────────────────────────

    #[test]
    fn listener_deleted_render_contains_name() {
        let d = ListenerDeleted { name: "http1".to_owned(), deleted: true };
        assert!(d.render_text().contains("http1"));
        assert!(d.render_text().contains("deleted"));
    }

    #[test]
    fn listener_deleted_serialises_deleted_true() {
        let d = ListenerDeleted { name: "x".to_owned(), deleted: true };
        let v = serde_json::to_value(&d).expect("serialise");
        assert_eq!(v["deleted"], true);
    }

    // ── build_create_body ─────────────────────────────────────────────────────

    #[test]
    fn build_create_body_http_uses_default_port_443() {
        let body =
            build_create_body("http1", "http", None, "0.0.0.0", None, None, None, false, None)
                .expect("build");
        assert_eq!(body["protocol"], "http");
        assert_eq!(body["config"]["port_bind"], 443);
        assert_eq!(body["config"]["name"], "http1");
    }

    #[test]
    fn build_create_body_http_respects_explicit_port() {
        let body =
            build_create_body("h2", "http", Some(8080), "10.0.0.1", None, None, None, true, None)
                .expect("build");
        assert_eq!(body["config"]["port_bind"], 8080);
        assert_eq!(body["config"]["secure"], true);
        assert_eq!(body["config"]["host_bind"], "10.0.0.1");
    }

    #[test]
    fn build_create_body_https_maps_to_http_protocol() {
        let body =
            build_create_body("h1", "https", Some(443), "0.0.0.0", None, None, None, true, None)
                .expect("build");
        assert_eq!(body["protocol"], "http");
    }

    #[test]
    fn build_create_body_dns_requires_domain() {
        let err = build_create_body("dns1", "dns", None, "0.0.0.0", None, None, None, false, None)
            .expect_err("should fail without domain");
        assert!(matches!(err, CliError::InvalidArgs(_)));
    }

    #[test]
    fn build_create_body_dns_with_domain() {
        let body = build_create_body(
            "dns1",
            "dns",
            Some(53),
            "0.0.0.0",
            Some("c2.evil.example"),
            None,
            None,
            false,
            None,
        )
        .expect("build");
        assert_eq!(body["protocol"], "dns");
        assert_eq!(body["config"]["domain"], "c2.evil.example");
        assert_eq!(body["config"]["port_bind"], 53);
    }

    #[test]
    fn build_create_body_dns_defaults_to_port_53() {
        let body = build_create_body(
            "dns1",
            "dns",
            None,
            "0.0.0.0",
            Some("c2.evil.example"),
            None,
            None,
            false,
            None,
        )
        .expect("build");
        assert_eq!(body["config"]["port_bind"], 53);
    }

    #[test]
    fn build_create_body_smb_requires_pipe_name() {
        let err = build_create_body("smb1", "smb", None, "0.0.0.0", None, None, None, false, None)
            .expect_err("should fail without pipe_name");
        assert!(matches!(err, CliError::InvalidArgs(_)));
    }

    #[test]
    fn build_create_body_smb_with_pipe_name() {
        let body = build_create_body(
            "smb1",
            "smb",
            None,
            "0.0.0.0",
            None,
            Some("my-pipe"),
            None,
            false,
            None,
        )
        .expect("build");
        assert_eq!(body["protocol"], "smb");
        assert_eq!(body["config"]["name"], "smb1");
        assert_eq!(body["config"]["pipe_name"], "my-pipe");
    }

    #[test]
    fn build_create_body_external_requires_endpoint() {
        let err =
            build_create_body("ext1", "external", None, "0.0.0.0", None, None, None, false, None)
                .expect_err("should fail without endpoint");
        assert!(matches!(err, CliError::InvalidArgs(_)));
    }

    #[test]
    fn build_create_body_external_with_endpoint() {
        let body = build_create_body(
            "ext1",
            "external",
            None,
            "0.0.0.0",
            None,
            None,
            Some("/bridge"),
            false,
            None,
        )
        .expect("build");
        assert_eq!(body["protocol"], "external");
        assert_eq!(body["config"]["endpoint"], "/bridge");
    }

    #[test]
    fn build_create_body_unknown_type_returns_invalid_args() {
        let err = build_create_body("x", "grpc", None, "0.0.0.0", None, None, None, false, None)
            .expect_err("unknown type should fail");
        assert!(matches!(err, CliError::InvalidArgs(_)));
    }

    #[test]
    fn build_create_body_config_json_overrides_flags() {
        let raw = r#"{"name":"http1","host_bind":"1.2.3.4","port_bind":9000,"host_rotation":"round-robin"}"#;
        let body = build_create_body(
            "ignored",
            "http",
            Some(80),
            "0.0.0.0",
            None,
            None,
            None,
            false,
            Some(raw),
        )
        .expect("build");
        assert_eq!(body["protocol"], "http");
        assert_eq!(body["config"]["port_bind"], 9000);
        assert_eq!(body["config"]["host_bind"], "1.2.3.4");
    }

    #[test]
    fn build_create_body_config_json_invalid_returns_error() {
        let err = build_create_body(
            "x",
            "http",
            None,
            "0.0.0.0",
            None,
            None,
            None,
            false,
            Some("{not json"),
        )
        .expect_err("bad json");
        assert!(matches!(err, CliError::InvalidArgs(_)));
    }

    #[test]
    fn build_create_body_config_json_dns_shape_rejected_for_http_type() {
        let raw =
            r#"{"name":"dns1","host_bind":"0.0.0.0","port_bind":53,"domain":"c2.example.com"}"#;
        let err =
            build_create_body("x", "http", None, "0.0.0.0", None, None, None, false, Some(raw))
                .expect_err("wrong schema for --type http");
        let CliError::InvalidArgs(msg) = err else {
            panic!("expected InvalidArgs, got {err:?}");
        };
        assert!(msg.contains("HTTP listener schema"), "expected HTTP schema hint, got: {msg}");
    }

    #[test]
    fn build_create_body_config_json_http_shape_rejected_for_dns_type() {
        let raw = r#"{"name":"h1","host_bind":"0.0.0.0","port_bind":443,"host_rotation":"round-robin","secure":false}"#;
        let err =
            build_create_body("x", "dns", None, "0.0.0.0", None, None, None, false, Some(raw))
                .expect_err("wrong schema for --type dns");
        let CliError::InvalidArgs(msg) = err else {
            panic!("expected InvalidArgs, got {err:?}");
        };
        assert!(msg.contains("DNS listener schema"), "expected DNS schema hint, got: {msg}");
    }

    #[test]
    fn build_create_body_config_json_unknown_protocol_skips_local_schema_validation() {
        let raw = r#"{"name":"x","host_bind":"0.0.0.0","port_bind":443}"#;
        let body = build_create_body(
            "ignored",
            "future_proto",
            None,
            "0.0.0.0",
            None,
            None,
            None,
            false,
            Some(raw),
        )
        .expect("unknown protocol should not run local serde validation");
        assert_eq!(body["protocol"], "future_proto");
        assert_eq!(body["config"]["port_bind"], 443);
    }

    // ── extract_info ──────────────────────────────────────────────────────────

    #[test]
    fn extract_info_http() {
        let raw = RawListenerSummary {
            name: "h".to_owned(),
            protocol: "http".to_owned(),
            state: RawListenerState { status: "Running".to_owned(), last_error: None },
            config: serde_json::json!({"protocol":"http","config":{"host_bind":"0.0.0.0","port_bind":443,"secure":false}}),
        };
        let info = extract_info(&raw);
        assert!(info.contains("443"));
        assert!(info.contains("0.0.0.0"));
        assert!(info.starts_with("http://"));
    }

    #[test]
    fn extract_info_https_shows_https_scheme() {
        let raw = RawListenerSummary {
            name: "h".to_owned(),
            protocol: "http".to_owned(),
            state: RawListenerState { status: "Running".to_owned(), last_error: None },
            config: serde_json::json!({"protocol":"http","config":{"host_bind":"0.0.0.0","port_bind":443,"secure":true}}),
        };
        let info = extract_info(&raw);
        assert!(info.starts_with("https://"));
    }

    #[test]
    fn extract_info_dns() {
        let raw = RawListenerSummary {
            name: "d".to_owned(),
            protocol: "dns".to_owned(),
            state: RawListenerState { status: "Stopped".to_owned(), last_error: None },
            config: serde_json::json!({"protocol":"dns","config":{"domain":"c2.evil.example","port_bind":53}}),
        };
        let info = extract_info(&raw);
        assert!(info.contains("c2.evil.example"));
        assert!(info.contains("53"));
    }

    #[test]
    fn extract_info_smb() {
        let raw = RawListenerSummary {
            name: "s".to_owned(),
            protocol: "smb".to_owned(),
            state: RawListenerState { status: "Created".to_owned(), last_error: None },
            config: serde_json::json!({"protocol":"smb","config":{"name":"s","pipe_name":"my-pipe"}}),
        };
        let info = extract_info(&raw);
        assert!(info.contains("my-pipe"));
    }

    #[test]
    fn extract_info_external() {
        let raw = RawListenerSummary {
            name: "e".to_owned(),
            protocol: "external".to_owned(),
            state: RawListenerState { status: "Created".to_owned(), last_error: None },
            config: serde_json::json!({"protocol":"external","config":{"name":"e","endpoint":"/bridge"}}),
        };
        let info = extract_info(&raw);
        assert!(info.contains("/bridge"));
    }

    // ── extract_info fallback '?' paths ──────────────────────────────────────

    fn make_raw(protocol: &str, config: serde_json::Value) -> RawListenerSummary {
        RawListenerSummary {
            name: "x".to_owned(),
            protocol: protocol.to_owned(),
            state: RawListenerState { status: "Created".to_owned(), last_error: None },
            config,
        }
    }

    #[test]
    fn extract_info_http_missing_host_bind_shows_question_mark() {
        // config inner has port_bind but no host_bind → host falls back to "?"
        let raw = make_raw(
            "http",
            serde_json::json!({"protocol":"http","config":{"port_bind":443,"secure":false}}),
        );
        let info = extract_info(&raw);
        assert!(info.contains('?'), "expected '?' in info, got: {info}");
        assert!(info.contains("443"));
    }

    #[test]
    fn extract_info_http_missing_port_bind_shows_question_mark() {
        // config inner has host_bind but no port_bind → port falls back to "?"
        let raw = make_raw(
            "http",
            serde_json::json!({"protocol":"http","config":{"host_bind":"0.0.0.0","secure":false}}),
        );
        let info = extract_info(&raw);
        assert!(info.contains('?'), "expected '?' in info, got: {info}");
        assert!(info.contains("0.0.0.0"));
    }

    #[test]
    fn extract_info_http_empty_config_shows_question_marks() {
        // Entire config object absent — both host and port fall back to "?"
        let raw = make_raw("http", serde_json::json!({}));
        let info = extract_info(&raw);
        assert!(info.contains('?'), "expected '?' in info, got: {info}");
    }

    #[test]
    fn extract_info_dns_missing_domain_shows_question_mark() {
        // DNS config present but domain field absent → domain falls back to "?"
        let raw = make_raw("dns", serde_json::json!({"protocol":"dns","config":{"port_bind":53}}));
        let info = extract_info(&raw);
        assert!(info.contains('?'), "expected '?' in info, got: {info}");
        assert!(info.contains("53"));
    }

    #[test]
    fn extract_info_dns_empty_config_shows_question_mark() {
        let raw = make_raw("dns", serde_json::json!({}));
        let info = extract_info(&raw);
        assert!(info.contains('?'), "expected '?' in info, got: {info}");
    }

    #[test]
    fn extract_info_smb_missing_pipe_name_shows_question_mark() {
        // SMB config present but pipe_name absent → falls back to "?"
        let raw = make_raw("smb", serde_json::json!({"protocol":"smb","config":{"name":"s"}}));
        let info = extract_info(&raw);
        assert!(info.contains('?'), "expected '?' in info, got: {info}");
    }

    #[test]
    fn extract_info_smb_empty_config_shows_question_mark() {
        let raw = make_raw("smb", serde_json::json!({}));
        let info = extract_info(&raw);
        assert!(info.contains('?'), "expected '?' in info, got: {info}");
    }

    #[test]
    fn extract_info_unknown_protocol_returns_empty_string() {
        // An unrecognised protocol (e.g. "grpc") hits the wildcard arm and
        // intentionally returns "".  This test documents that behaviour so a
        // future maintainer knows the empty string is deliberate.
        let raw = make_raw("grpc", serde_json::json!({"protocol":"grpc","config":{}}));
        let info = extract_info(&raw);
        assert_eq!(info, "", "unknown protocol should return empty string, got: {info}");
    }

    // ── from_raw helpers ──────────────────────────────────────────────────────

    #[test]
    fn listener_row_from_raw_maps_all_fields() {
        let raw = RawListenerSummary {
            name: "http1".to_owned(),
            protocol: "http".to_owned(),
            state: RawListenerState { status: "Running".to_owned(), last_error: None },
            config: serde_json::json!({"protocol":"http","config":{"host_bind":"0.0.0.0","port_bind":443,"secure":false}}),
        };
        let row = listener_row_from_raw(raw);
        assert_eq!(row.name, "http1");
        assert_eq!(row.protocol, "http");
        assert_eq!(row.status, "Running");
        assert!(!row.info.is_empty());
    }

    #[test]
    fn listener_detail_from_raw_preserves_last_error() {
        let raw = RawListenerSummary {
            name: "bad".to_owned(),
            protocol: "http".to_owned(),
            state: RawListenerState {
                status: "Error".to_owned(),
                last_error: Some("bind failed: address in use".to_owned()),
            },
            config: serde_json::json!({}),
        };
        let detail = listener_detail_from_raw(raw);
        assert_eq!(detail.status, "Error");
        assert_eq!(detail.last_error.as_deref(), Some("bind failed: address in use"));
    }

    // ── ListenerAccessInfo ────────────────────────────────────────────────────

    #[test]
    fn raw_listener_access_response_deserialises_server_shape() {
        let json = r#"{"listener_name":"http1","allowed_operators":["alice","bob"]}"#;
        let raw: RawListenerAccessResponse = serde_json::from_str(json).expect("deserialise");
        assert_eq!(raw.listener_name, "http1");
        assert_eq!(raw.allowed_operators, vec!["alice", "bob"]);
    }

    #[test]
    fn listener_access_info_renders_text() {
        let info = ListenerAccessInfo {
            listener_name: "l1".to_owned(),
            allowed_operators: vec!["u1".to_owned()],
        };
        let t = info.render_text();
        assert!(t.contains("l1"));
        assert!(t.contains("u1"));
    }

    #[test]
    fn listener_access_info_empty_allows_all_text() {
        let info = ListenerAccessInfo { listener_name: "l2".to_owned(), allowed_operators: vec![] };
        assert!(info.render_text().contains("no operator restrictions"));
    }
}
