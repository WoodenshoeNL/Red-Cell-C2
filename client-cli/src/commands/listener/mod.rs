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

pub mod create;
pub mod lifecycle;
pub mod list;

use serde::{Deserialize, Serialize};

use crate::ListenerCommands;
use crate::client::ApiClient;
use crate::error::EXIT_SUCCESS;
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
pub(crate) struct RawListenerAccessResponse {
    pub(crate) listener_name: String,
    pub(crate) allowed_operators: Vec<String>,
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
        ListenerCommands::List => match list::list(client).await {
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

        ListenerCommands::Show { name } => match list::show(client, &name).await {
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
            match create::create(
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

        ListenerCommands::Start { name } => match lifecycle::start(client, &name).await {
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

        ListenerCommands::Stop { name } => match lifecycle::stop(client, &name).await {
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

        ListenerCommands::Delete { name } => match lifecycle::delete(client, &name).await {
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

        ListenerCommands::Access { name } => match lifecycle::get_access(client, &name).await {
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
            match lifecycle::set_access(client, &name, &allow_operator).await {
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
