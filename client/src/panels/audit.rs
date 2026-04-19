//! Audit log viewer panel — queries `GET /api/v1/audit` and displays a paginated,
//! filterable table of operator actions recorded by the teamserver.
//!
//! # Authentication
//!
//! The REST API requires an `x-api-key` header.  The key is read from
//! [`LocalConfig::api_key`] and can be entered inline in the panel when missing.
//!
//! # Pagination
//!
//! The panel uses the server's `total`, `offset`, and `limit` fields.  The
//! Previous/Next buttons shift the offset by `limit` rows.  An explicit
//! "Go to page" control is not needed for the initial implementation.

use eframe::egui::{self, Color32, RichText};
use serde::Deserialize;
use tokio::sync::oneshot;
use tracing::warn;

use crate::ClientApp;
use crate::local_config::LocalConfig;
use crate::state::session::{AuditFetchPayload, AuditFetchStatus, AuditLogPanelState, AuditRow};
use crate::transport::AppState;

// ── Column widths ──────────────────────────────────────────────────────────────

const COL_TIME: f32 = 170.0;
const COL_ACTOR: f32 = 130.0;
const COL_ACTION: f32 = 160.0;
const COL_TARGET: f32 = 100.0;
const COL_AGENT: f32 = 110.0;
const COL_RESULT: f32 = 70.0;

const API_KEY_HEADER: &str = "x-api-key";

// ── Wire types (mirrors teamserver audit types) ────────────────────────────────

/// Mirrors `teamserver::audit::AuditRecord`.
#[derive(Debug, Deserialize)]
struct WireAuditRecord {
    id: i64,
    actor: String,
    action: String,
    target_kind: String,
    target_id: Option<String>,
    agent_id: Option<String>,
    command: Option<String>,
    result_status: String,
    occurred_at: String,
}

/// Mirrors `teamserver::audit::AuditPage`.
#[derive(Debug, Deserialize)]
struct WireAuditPage {
    total: usize,
    limit: usize,
    offset: usize,
    items: Vec<WireAuditRecord>,
}

// ── URL helpers ────────────────────────────────────────────────────────────────

/// Convert a WebSocket URL to the HTTP base URL.
///
/// `wss://host:port/anything` → `https://host:port`
/// `ws://host:port/anything`  → `http://host:port`
fn ws_url_to_http_base(ws_url: &str) -> Option<String> {
    let url = url::Url::parse(ws_url).ok()?;
    let scheme = match url.scheme() {
        "wss" => "https",
        "ws" => "http",
        _ => return None,
    };
    let host = url.host_str()?;
    match url.port() {
        Some(port) => Some(format!("{scheme}://{host}:{port}")),
        None => Some(format!("{scheme}://{host}")),
    }
}

// ── Fetch task ─────────────────────────────────────────────────────────────────

/// Fetch one page of audit log entries from the teamserver REST API.
///
/// Runs in a Tokio background task; sends the result through `tx`.
#[allow(clippy::too_many_arguments)]
async fn fetch_audit_page(
    client: reqwest::Client,
    http_base: String,
    api_key: String,
    actor: Option<String>,
    action: Option<String>,
    agent_id: Option<String>,
    offset: usize,
    limit: usize,
    tx: oneshot::Sender<Result<AuditFetchPayload, String>>,
) {
    let mut url = format!("{http_base}/api/v1/audit?limit={limit}&offset={offset}");
    if let Some(a) = actor.filter(|s| !s.trim().is_empty()) {
        url.push_str(&format!("&actor={}", urlencoding_encode(&a)));
    }
    if let Some(a) = action.filter(|s| !s.trim().is_empty()) {
        url.push_str(&format!("&action={}", urlencoding_encode(&a)));
    }
    if let Some(id) = agent_id.filter(|s| !s.trim().is_empty()) {
        url.push_str(&format!("&agent_id={}", urlencoding_encode(&id)));
    }

    let resp = client.get(&url).header(API_KEY_HEADER, &api_key).send().await;

    let response = match resp {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.send(Err(format!("request failed: {e}")));
            return;
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        let _ = tx.send(Err(format!("server returned {status}: {body}")));
        return;
    }

    let page: WireAuditPage = match response.json().await {
        Ok(p) => p,
        Err(e) => {
            let _ = tx.send(Err(format!("failed to parse response: {e}")));
            return;
        }
    };

    let rows = page
        .items
        .into_iter()
        .map(|r| AuditRow {
            id: r.id,
            occurred_at: r.occurred_at,
            actor: r.actor,
            action: r.action,
            target_kind: r.target_kind,
            target_id: r.target_id,
            agent_id: r.agent_id,
            command: r.command,
            result_status: r.result_status,
        })
        .collect();

    let _ = tx.send(Ok(AuditFetchPayload {
        rows,
        total: page.total,
        offset: page.offset,
        limit: page.limit,
    }));
}

/// Simple percent-encoder for query parameter values (encodes space, `&`, `=`, `+`).
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ── Panel rendering ────────────────────────────────────────────────────────────

impl ClientApp {
    /// Render the audit log viewer dock tab.
    pub(crate) fn render_audit_log_panel(
        &mut self,
        ui: &mut egui::Ui,
        state: &AppState,
        local_config: &LocalConfig,
    ) {
        let panel = &mut self.session_panel.audit_log_panel;

        // Poll for a completed fetch result.
        if let Some(mut rx) = panel.result_rx.take() {
            match rx.try_recv() {
                Ok(Ok(payload)) => {
                    panel.rows = payload.rows;
                    panel.total = payload.total;
                    panel.offset = payload.offset;
                    panel.limit = payload.limit;
                    panel.fetch_status = AuditFetchStatus::Idle;
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "audit log fetch failed");
                    panel.fetch_status = AuditFetchStatus::Error(e);
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    // Still running — put it back.
                    panel.result_rx = Some(rx);
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    panel.fetch_status =
                        AuditFetchStatus::Error("fetch task dropped unexpectedly".to_owned());
                }
            }
        }

        // Initialise limit on first render.
        if panel.limit == 0 {
            panel.limit = AuditLogPanelState::DEFAULT_LIMIT;
        }

        // Determine the API key: prefer LocalConfig, fall back to the inline input.
        let resolved_api_key =
            local_config.api_key.clone().filter(|k| !k.trim().is_empty()).or_else(|| {
                let trimmed = panel.api_key_input.trim().to_owned();
                if trimmed.is_empty() { None } else { Some(trimmed) }
            });
        let has_api_key = resolved_api_key.is_some();

        let http_base = state.server_url.as_str().pipe(ws_url_to_http_base);

        // Auto-fetch on first open when credentials are available.
        if panel.rows.is_empty()
            && panel.result_rx.is_none()
            && resolved_api_key.is_some()
            && http_base.is_some()
            && matches!(panel.fetch_status, AuditFetchStatus::Idle)
        {
            trigger_fetch(
                panel,
                http_base.clone().unwrap_or_default(),
                resolved_api_key.clone().unwrap_or_default(),
                ui.ctx().clone(),
            );
        }

        // ── Toolbar ──────────────────────────────────────────────────────────
        ui.horizontal(|ui| {
            ui.heading(RichText::new("Audit Log").strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let fetching = matches!(panel.fetch_status, AuditFetchStatus::Fetching)
                    || panel.result_rx.is_some();
                if ui
                    .add_enabled(
                        !fetching && has_api_key && http_base.is_some(),
                        egui::Button::new("Refresh"),
                    )
                    .clicked()
                {
                    trigger_fetch(
                        panel,
                        http_base.clone().unwrap_or_default(),
                        resolved_api_key.clone().unwrap_or_default(),
                        ui.ctx().clone(),
                    );
                }
                if ui.button("⚙ API Key").clicked() {
                    panel.show_api_key_input = !panel.show_api_key_input;
                }
            });
        });

        ui.add_space(4.0);

        // ── API key setup strip ───────────────────────────────────────────────
        if local_config.api_key.as_ref().is_none_or(|k| k.trim().is_empty())
            || panel.show_api_key_input
        {
            ui.horizontal(|ui| {
                ui.label(RichText::new("API Key:").small());
                let resp = ui.add_sized(
                    [280.0, 18.0],
                    egui::TextEdit::singleline(&mut panel.api_key_input)
                        .password(true)
                        .hint_text("paste key from HCL profile"),
                );
                if resp.changed() {
                    // Clear any previous error when the user edits the key.
                    if matches!(panel.fetch_status, AuditFetchStatus::Error(_)) {
                        panel.fetch_status = AuditFetchStatus::Idle;
                    }
                }
                ui.label(
                    RichText::new("(not saved — set api_key in client.toml to persist)")
                        .weak()
                        .small(),
                );
            });
            ui.add_space(2.0);
        }

        // ── Filter bar ────────────────────────────────────────────────────────
        ui.horizontal(|ui| {
            ui.label(RichText::new("Actor:").small());
            ui.add_sized(
                [120.0, 18.0],
                egui::TextEdit::singleline(&mut panel.filter_actor).hint_text("username"),
            );
            ui.label(RichText::new("Action:").small());
            ui.add_sized(
                [120.0, 18.0],
                egui::TextEdit::singleline(&mut panel.filter_action).hint_text("e.g. agent.task"),
            );
            ui.label(RichText::new("Agent:").small());
            ui.add_sized(
                [110.0, 18.0],
                egui::TextEdit::singleline(&mut panel.filter_agent_id).hint_text("hex id"),
            );

            let fetching = matches!(panel.fetch_status, AuditFetchStatus::Fetching)
                || panel.result_rx.is_some();
            if ui
                .add_enabled(
                    !fetching && has_api_key && http_base.is_some(),
                    egui::Button::new("Search"),
                )
                .clicked()
            {
                panel.offset = 0;
                trigger_fetch(
                    panel,
                    http_base.clone().unwrap_or_default(),
                    resolved_api_key.clone().unwrap_or_default(),
                    ui.ctx().clone(),
                );
            }
        });

        ui.add_space(2.0);

        // ── Status / error banner ─────────────────────────────────────────────
        match &panel.fetch_status {
            AuditFetchStatus::Fetching => {
                ui.label(RichText::new("Fetching…").weak().small());
            }
            AuditFetchStatus::Error(e) => {
                ui.label(
                    RichText::new(format!("Error: {e}"))
                        .color(Color32::from_rgb(230, 80, 80))
                        .small(),
                );
            }
            AuditFetchStatus::Idle => {}
        }

        if !has_api_key {
            ui.label(
                RichText::new(
                    "No API key configured. Enter one above or set api_key in client.toml.",
                )
                .color(Color32::from_rgb(232, 182, 83))
                .small(),
            );
        }

        // ── Table header ──────────────────────────────────────────────────────
        ui.separator();
        ui.horizontal(|ui| {
            for (label, width) in [
                ("Time (UTC)", COL_TIME),
                ("Actor", COL_ACTOR),
                ("Action", COL_ACTION),
                ("Target", COL_TARGET),
                ("Agent ID", COL_AGENT),
                ("Result", COL_RESULT),
            ] {
                ui.add_sized(
                    [width, 18.0],
                    egui::Label::new(
                        RichText::new(label).strong().color(Color32::from_rgb(180, 180, 200)),
                    ),
                );
            }
        });
        ui.separator();

        // ── Table body ────────────────────────────────────────────────────────
        if panel.rows.is_empty()
            && matches!(panel.fetch_status, AuditFetchStatus::Idle)
            && panel.result_rx.is_none()
        {
            egui::ScrollArea::vertical().id_salt("audit_scroll").show(ui, |ui| {
                ui.label(
                    RichText::new("No entries loaded. Press Refresh to fetch the audit log.")
                        .weak(),
                );
            });
        } else {
            egui::ScrollArea::vertical().id_salt("audit_scroll").show(ui, |ui| {
                for row in &panel.rows {
                    let result_color = if row.result_status == "success" {
                        Color32::from_rgb(110, 199, 141)
                    } else {
                        Color32::from_rgb(230, 80, 80)
                    };

                    ui.push_id(row.id, |ui| {
                        ui.horizontal(|ui| {
                            let ts = row.occurred_at.trim_end_matches('Z').replace('T', " ");
                            ui.add_sized(
                                [COL_TIME, 16.0],
                                egui::Label::new(RichText::new(&ts).monospace().small()),
                            );
                            ui.add_sized(
                                [COL_ACTOR, 16.0],
                                egui::Label::new(RichText::new(&row.actor).small()),
                            );

                            let action_detail = match &row.command {
                                Some(cmd) => format!("{} / {cmd}", row.action),
                                None => row.action.clone(),
                            };
                            ui.add_sized(
                                [COL_ACTION, 16.0],
                                egui::Label::new(RichText::new(action_detail).small()),
                            );

                            let target = match &row.target_id {
                                Some(id) => format!("{} {id}", row.target_kind),
                                None => row.target_kind.clone(),
                            };
                            ui.add_sized(
                                [COL_TARGET, 16.0],
                                egui::Label::new(RichText::new(target).small()),
                            );

                            ui.add_sized(
                                [COL_AGENT, 16.0],
                                egui::Label::new(
                                    RichText::new(row.agent_id.as_deref().unwrap_or("—"))
                                        .monospace()
                                        .small(),
                                ),
                            );

                            ui.add_sized(
                                [COL_RESULT, 16.0],
                                egui::Label::new(
                                    RichText::new(&row.result_status).color(result_color).small(),
                                ),
                            );
                        });
                    }); // push_id
                }
            });
        }

        // ── Pagination footer ─────────────────────────────────────────────────
        if panel.total > 0 || !panel.rows.is_empty() {
            ui.separator();
            ui.horizontal(|ui| {
                let fetching = matches!(panel.fetch_status, AuditFetchStatus::Fetching)
                    || panel.result_rx.is_some();
                let page_start = panel.offset + 1;
                let page_end =
                    (panel.offset + panel.rows.len()).min(panel.total.max(panel.rows.len()));
                ui.label(
                    RichText::new(format!("{page_start}–{page_end} of {}", panel.total)).small(),
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let has_next = panel.offset + panel.limit < panel.total;
                    let has_prev = panel.offset > 0;

                    if ui
                        .add_enabled(
                            !fetching && has_api_key && has_next,
                            egui::Button::new("Next →"),
                        )
                        .clicked()
                    {
                        panel.offset += panel.limit;
                        trigger_fetch(
                            panel,
                            http_base.clone().unwrap_or_default(),
                            resolved_api_key.clone().unwrap_or_default(),
                            ui.ctx().clone(),
                        );
                    }
                    if ui
                        .add_enabled(
                            !fetching && has_api_key && has_prev,
                            egui::Button::new("← Prev"),
                        )
                        .clicked()
                    {
                        panel.offset = panel.offset.saturating_sub(panel.limit);
                        trigger_fetch(
                            panel,
                            http_base.unwrap_or_default(),
                            resolved_api_key.unwrap_or_default(),
                            ui.ctx().clone(),
                        );
                    }
                });
            });
        }
    }
}

/// Spawn a background fetch task and arm the result channel on `panel`.
fn trigger_fetch(
    panel: &mut AuditLogPanelState,
    http_base: String,
    api_key: String,
    ctx: egui::Context,
) {
    let (tx, rx) = oneshot::channel();
    panel.result_rx = Some(rx);
    panel.fetch_status = AuditFetchStatus::Fetching;

    let actor = panel.filter_actor.trim().to_owned();
    let action = panel.filter_action.trim().to_owned();
    let agent_id = panel.filter_agent_id.trim().to_owned();
    let offset = panel.offset;
    let limit = panel.limit;
    let client = panel.http_client.clone();

    tokio::spawn(async move {
        fetch_audit_page(
            client,
            http_base,
            api_key,
            if actor.is_empty() { None } else { Some(actor) },
            if action.is_empty() { None } else { Some(action) },
            if agent_id.is_empty() { None } else { Some(agent_id) },
            offset,
            limit,
            tx,
        )
        .await;
        ctx.request_repaint();
    });
}

// ── Extension trait helper ─────────────────────────────────────────────────────

/// Convenience `.pipe()` for `Option<T>` to allow chained method calls without
/// binding the value to a variable.
trait Pipe: Sized {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R,
    {
        f(self)
    }
}

impl<T> Pipe for T {}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_to_http_base_converts_wss() {
        assert_eq!(
            ws_url_to_http_base("wss://ops.example.com:8443/havoc/"),
            Some("https://ops.example.com:8443".to_owned())
        );
    }

    #[test]
    fn ws_url_to_http_base_converts_ws() {
        assert_eq!(
            ws_url_to_http_base("ws://127.0.0.1:8080/havoc/"),
            Some("http://127.0.0.1:8080".to_owned())
        );
    }

    #[test]
    fn ws_url_to_http_base_no_explicit_port() {
        assert_eq!(
            ws_url_to_http_base("wss://ops.example.com/havoc/"),
            Some("https://ops.example.com".to_owned())
        );
    }

    #[test]
    fn ws_url_to_http_base_rejects_non_ws_scheme() {
        assert_eq!(ws_url_to_http_base("https://example.com/"), None);
    }

    #[test]
    fn ws_url_to_http_base_rejects_garbage() {
        assert_eq!(ws_url_to_http_base("not a url"), None);
    }

    #[test]
    fn urlencoding_encode_passthrough_safe_chars() {
        assert_eq!(urlencoding_encode("alice"), "alice");
        assert_eq!(urlencoding_encode("abc-123"), "abc-123");
    }

    #[test]
    fn urlencoding_encode_encodes_space_and_ampersand() {
        assert_eq!(urlencoding_encode("alice bob"), "alice%20bob");
        assert_eq!(urlencoding_encode("a&b"), "a%26b");
    }

    #[test]
    fn audit_log_panel_state_default_limit() {
        assert_eq!(AuditLogPanelState::DEFAULT_LIMIT, 50);
    }

    #[test]
    fn audit_log_panel_state_default_is_idle() {
        let s = AuditLogPanelState::default();
        assert!(matches!(s.fetch_status, AuditFetchStatus::Idle));
        assert!(s.rows.is_empty());
        assert_eq!(s.offset, 0);
        assert_eq!(s.total, 0);
    }

    #[test]
    fn pagination_next_advances_offset_by_limit() {
        let mut panel =
            AuditLogPanelState { limit: 50, offset: 0, total: 200, ..Default::default() };
        panel.offset += panel.limit;
        assert_eq!(panel.offset, 50);
    }

    #[test]
    fn pagination_prev_saturates_at_zero() {
        let mut panel = AuditLogPanelState { limit: 50, offset: 0, ..Default::default() };
        panel.offset = panel.offset.saturating_sub(panel.limit);
        assert_eq!(panel.offset, 0);
    }

    #[test]
    fn pagination_last_page_detection() {
        let panel = AuditLogPanelState { limit: 50, offset: 150, total: 200, ..Default::default() };
        let has_next = panel.offset + panel.limit < panel.total;
        assert!(!has_next); // 150 + 50 == 200, not < 200
    }

    #[test]
    fn pagination_mid_page_detection() {
        let panel = AuditLogPanelState { limit: 50, offset: 100, total: 200, ..Default::default() };
        let has_next = panel.offset + panel.limit < panel.total;
        assert!(has_next);
    }
}
