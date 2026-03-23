//! `red-cell-cli log` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `log list [filters]` | `GET /audit/log?...` | newest-first, filterable |
//! | `log tail` | `GET /audit/log?limit=20` | last 20 entries |
//! | `log tail --follow` | poll `GET /audit/log?since=<ts>` | stream JSON lines |

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::instrument;

use crate::AuditCommands;
use crate::client::ApiClient;
use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{OutputFormat, TextRow, print_error, print_success};

/// Number of entries fetched by `log tail` (without --follow).
const TAIL_LIMIT: u32 = 20;
/// Polling interval for `log tail --follow`.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

// ── raw API response shapes ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RawAuditEntry {
    ts: String,
    operator: String,
    action: String,
    agent_id: Option<String>,
    detail: Option<String>,
}

// ── public output types ───────────────────────────────────────────────────────

/// A single audit log entry returned by `log list` / `log tail`.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    /// ISO 8601 UTC timestamp of the event.
    pub ts: String,
    /// Operator username who performed the action.
    pub operator: String,
    /// Action type (e.g. `"exec"`, `"kill"`, `"login"`).
    pub action: String,
    /// Agent ID the action was performed on, if applicable.
    pub agent_id: Option<String>,
    /// Human-readable detail about the action.
    pub detail: Option<String>,
}

impl TextRow for AuditEntry {
    fn headers() -> Vec<&'static str> {
        vec!["Timestamp", "Operator", "Action", "Agent ID", "Detail"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.ts.clone(),
            self.operator.clone(),
            self.action.clone(),
            self.agent_id.clone().unwrap_or_default(),
            self.detail.clone().unwrap_or_default(),
        ]
    }
}

// ── top-level dispatcher ──────────────────────────────────────────────────────

/// Dispatch an [`AuditCommands`] variant and return a process exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: AuditCommands) -> i32 {
    match action {
        AuditCommands::List { operator, action, agent, since, limit } => {
            match list(
                client,
                limit,
                since.as_deref(),
                operator.as_deref(),
                agent.as_deref(),
                action.as_deref(),
            )
            .await
            {
                Ok(data) => {
                    print_success(fmt, &data);
                    EXIT_SUCCESS
                }
                Err(e) => {
                    print_error(&e);
                    e.exit_code()
                }
            }
        }

        AuditCommands::Tail { follow } => {
            if follow {
                tail_follow(client, fmt).await
            } else {
                match list(client, TAIL_LIMIT, None, None, None, None).await {
                    Ok(data) => {
                        print_success(fmt, &data);
                        EXIT_SUCCESS
                    }
                    Err(e) => {
                        print_error(&e);
                        e.exit_code()
                    }
                }
            }
        }
    }
}

// ── command implementations ───────────────────────────────────────────────────

/// `log list` — fetch audit log entries with optional filters.
///
/// Entries are returned newest-first.
///
/// # Examples
/// ```text
/// red-cell-cli log list
/// red-cell-cli log list --operator alice --limit 50
/// red-cell-cli log list --since 2026-03-21T00:00:00Z --agent abc123
/// ```
#[instrument(skip(client))]
async fn list(
    client: &ApiClient,
    limit: u32,
    since: Option<&str>,
    operator: Option<&str>,
    agent_id: Option<&str>,
    action: Option<&str>,
) -> Result<Vec<AuditEntry>, CliError> {
    let mut params: Vec<String> = vec![format!("limit={limit}")];

    if let Some(s) = since {
        params.push(format!("since={}", percent_encode(s)));
    }
    if let Some(op) = operator {
        params.push(format!("operator={}", percent_encode(op)));
    }
    if let Some(aid) = agent_id {
        params.push(format!("agent_id={}", percent_encode(aid)));
    }
    if let Some(act) = action {
        params.push(format!("action={}", percent_encode(act)));
    }

    let path = format!("/audit/log?{}", params.join("&"));
    let raw: Vec<RawAuditEntry> = client.get(&path).await?;
    Ok(raw.into_iter().map(audit_entry_from_raw).collect())
}

/// `log tail --follow` — print the last 20 entries then stream new ones as
/// JSON lines until Ctrl-C.
///
/// Uses the timestamp of the most recent entry as a cursor for incremental
/// polling so that each entry is emitted exactly once.
///
/// # Examples
/// ```text
/// red-cell-cli log tail --follow
/// ```
async fn tail_follow(client: &ApiClient, fmt: &OutputFormat) -> i32 {
    // Fetch initial batch of 20 entries.
    let initial_result = tokio::select! {
        result = list(client, TAIL_LIMIT, None, None, None, None) => result,
        _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
    };

    let mut cursor: Option<String> = match initial_result {
        Err(e) => {
            print_error(&e);
            return e.exit_code();
        }
        Ok(entries) => {
            // Print existing entries the same way as a plain `log tail`.
            let latest_ts = entries.first().map(|e| e.ts.clone());
            for entry in &entries {
                print_entry_line(fmt, entry);
            }
            latest_ts
        }
    };

    // Poll for new entries using the cursor timestamp.
    loop {
        let sleep_fut = sleep(POLL_INTERVAL);
        tokio::select! {
            _ = sleep_fut => {}
            _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
        }

        let poll_result = tokio::select! {
            result = list(client, 100, cursor.as_deref(), None, None, None) => result,
            _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
        };

        match poll_result {
            Err(e) => {
                print_error(&e);
                return e.exit_code();
            }
            Ok(entries) => {
                for entry in &entries {
                    print_entry_line(fmt, entry);
                    cursor = Some(entry.ts.clone());
                }
            }
        }
    }
}

/// Write a single audit entry to stdout as a JSON line (JSON mode) or a
/// formatted text line (text mode).
fn print_entry_line(fmt: &OutputFormat, entry: &AuditEntry) {
    match fmt {
        OutputFormat::Json => {
            let line = serde_json::json!({
                "ts":       entry.ts,
                "operator": entry.operator,
                "action":   entry.action,
                "agent_id": entry.agent_id,
                "detail":   entry.detail,
            });
            match serde_json::to_string(&line) {
                Ok(s) => println!("{s}"),
                Err(_) => println!(r#"{{"ts":"","operator":"","action":""}}"#),
            }
        }
        OutputFormat::Text => {
            let agent = entry.agent_id.as_deref().unwrap_or("-");
            let detail = entry.detail.as_deref().unwrap_or("");
            println!(
                "[{}]  {:20}  {:16}  agent={}  {}",
                entry.ts, entry.operator, entry.action, agent, detail
            );
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn audit_entry_from_raw(raw: RawAuditEntry) -> AuditEntry {
    AuditEntry {
        ts: raw.ts,
        operator: raw.operator,
        action: raw.action,
        agent_id: raw.agent_id,
        detail: raw.detail,
    }
}

/// Percent-encode a query-parameter value.
///
/// Characters safe in a URL query string are left unchanged; all others are
/// encoded as `%XX`.  The set of safe characters matches RFC 3986 unreserved
/// characters plus `:` (for ISO 8601 timestamps).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' => {
                out.push(byte as char)
            }
            b => {
                out.push('%');
                out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
                out.push(char::from_digit((b & 0xf) as u32, 16).unwrap_or('0'));
            }
        }
    }
    out
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::TextRender as _;

    // ── audit_entry_from_raw ──────────────────────────────────────────────────

    #[test]
    fn audit_entry_from_raw_maps_all_fields() {
        let raw = RawAuditEntry {
            ts: "2026-03-21T12:00:00Z".to_owned(),
            operator: "alice".to_owned(),
            action: "exec".to_owned(),
            agent_id: Some("abc123".to_owned()),
            detail: Some("whoami".to_owned()),
        };
        let entry = audit_entry_from_raw(raw);
        assert_eq!(entry.ts, "2026-03-21T12:00:00Z");
        assert_eq!(entry.operator, "alice");
        assert_eq!(entry.action, "exec");
        assert_eq!(entry.agent_id.as_deref(), Some("abc123"));
        assert_eq!(entry.detail.as_deref(), Some("whoami"));
    }

    #[test]
    fn audit_entry_from_raw_handles_none_fields() {
        let raw = RawAuditEntry {
            ts: "2026-03-21T00:00:00Z".to_owned(),
            operator: "bob".to_owned(),
            action: "login".to_owned(),
            agent_id: None,
            detail: None,
        };
        let entry = audit_entry_from_raw(raw);
        assert!(entry.agent_id.is_none());
        assert!(entry.detail.is_none());
    }

    // ── AuditEntry / TextRow ──────────────────────────────────────────────────

    #[test]
    fn audit_entry_headers_match_row_length() {
        let entry = AuditEntry {
            ts: "2026-03-21T12:00:00Z".to_owned(),
            operator: "alice".to_owned(),
            action: "exec".to_owned(),
            agent_id: Some("abc123".to_owned()),
            detail: Some("whoami".to_owned()),
        };
        assert_eq!(AuditEntry::headers().len(), entry.row().len());
    }

    #[test]
    fn audit_entry_row_uses_empty_string_for_none_agent_id() {
        let entry = AuditEntry {
            ts: "2026-03-21T12:00:00Z".to_owned(),
            operator: "alice".to_owned(),
            action: "login".to_owned(),
            agent_id: None,
            detail: None,
        };
        let row = entry.row();
        assert_eq!(row[3], ""); // agent_id column
        assert_eq!(row[4], ""); // detail column
    }

    #[test]
    fn audit_entry_serialises_all_fields() {
        let entry = AuditEntry {
            ts: "2026-03-21T12:00:00Z".to_owned(),
            operator: "carol".to_owned(),
            action: "kill".to_owned(),
            agent_id: Some("xyz789".to_owned()),
            detail: Some("SIGTERM".to_owned()),
        };
        let v = serde_json::to_value(&entry).expect("serialise");
        assert_eq!(v["ts"], "2026-03-21T12:00:00Z");
        assert_eq!(v["operator"], "carol");
        assert_eq!(v["action"], "kill");
        assert_eq!(v["agent_id"], "xyz789");
        assert_eq!(v["detail"], "SIGTERM");
    }

    #[test]
    fn vec_audit_entry_renders_table_with_data() {
        let entries = vec![AuditEntry {
            ts: "2026-03-21T12:00:00Z".to_owned(),
            operator: "dave".to_owned(),
            action: "exec".to_owned(),
            agent_id: Some("abc".to_owned()),
            detail: Some("id".to_owned()),
        }];
        let rendered = entries.render_text();
        assert!(rendered.contains("dave"));
        assert!(rendered.contains("exec"));
        assert!(rendered.contains("abc"));
    }

    #[test]
    fn vec_audit_entry_empty_renders_none() {
        let entries: Vec<AuditEntry> = vec![];
        assert_eq!(entries.render_text(), "(none)");
    }

    // ── percent_encode ────────────────────────────────────────────────────────

    #[test]
    fn percent_encode_leaves_safe_chars_unchanged() {
        assert_eq!(percent_encode("abc123-_.~:"), "abc123-_.~:");
    }

    #[test]
    fn percent_encode_encodes_space() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
    }

    #[test]
    fn percent_encode_encodes_ampersand_and_equals() {
        assert_eq!(percent_encode("a=b&c=d"), "a%3db%26c%3dd");
    }

    #[test]
    fn percent_encode_iso8601_timestamp_unchanged() {
        // Colons in ISO 8601 timestamps must not be encoded.
        assert_eq!(percent_encode("2026-03-21T12:00:00Z"), "2026-03-21T12:00:00Z");
    }

    #[test]
    fn percent_encode_at_sign_in_operator_name() {
        // @ is not in the safe set and must be encoded.
        let encoded = percent_encode("alice@example.com");
        assert!(encoded.contains('%'));
        assert!(!encoded.contains('@'));
    }
}
