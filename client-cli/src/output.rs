//! Output formatting for `red-cell-cli`.
//!
//! # JSON mode (default)
//!
//! All commands write a single JSON object to **stdout**:
//!
//! ```json
//! {"ok": true, "data": <command-specific payload>}
//! ```
//!
//! # Text mode (`--output text`)
//!
//! Types that implement [`TextRender`] control their own human-readable
//! representation.  List types use the [`TextRow`] blanket impl which builds
//! a [`comfy_table::Table`].  Error format on stderr is always JSON regardless
//! of mode.
//!
//! # Error output
//!
//! Failures are always written as JSON to **stderr**, regardless of `--output`:
//!
//! ```json
//! {"ok": false, "error": "ERROR_CODE", "message": "human readable"}
//! ```
//!
//! stdout and stderr are never mixed.

use comfy_table::{Cell, ContentArrangement, Table};
use serde::Serialize;

use crate::error::CliError;

// ── output format ─────────────────────────────────────────────────────────────

/// Output format selected via `--output`.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    /// Structured JSON (machine-readable, default).
    Json,
    /// Human-readable text tables.
    Text,
}

// ── rendering traits ──────────────────────────────────────────────────────────

/// A type that can render itself as human-readable text for `--output text`.
///
/// Implement this on every command output type so that [`print_success`] can
/// produce a readable representation in text mode.
pub trait TextRender {
    /// Render `self` as a human-readable string.
    fn render_text(&self) -> String;
}

/// A type that can be rendered as a single row in a table.
///
/// Implement this on per-item types used in list commands.  The blanket impl
/// `TextRender for Vec<T: TextRow>` will then handle the full list.
pub trait TextRow {
    /// Column headers (shared across all rows).
    fn headers() -> Vec<&'static str>;
    /// Cell values for this row, in the same order as [`TextRow::headers`].
    fn row(&self) -> Vec<String>;
}

/// Blanket impl: a `Vec<T>` is text-renderable whenever `T: TextRow`.
///
/// An empty slice renders as `"(none)"` to avoid a blank screen.
impl<T: TextRow> TextRender for Vec<T> {
    fn render_text(&self) -> String {
        if self.is_empty() {
            return "(none)".to_owned();
        }
        build_table(&T::headers(), self.iter().map(|item| item.row())).to_string()
    }
}

// ── public output functions ───────────────────────────────────────────────────

/// Write a successful response to stdout.
///
/// * **JSON mode** — emits `{"ok": true, "data": <payload>}`.
/// * **Text mode** — calls [`TextRender::render_text`] and prints the result.
///
/// Stdout and stderr are never mixed; no prose is written to stdout in JSON
/// mode.
pub fn print_success<T: Serialize + TextRender>(format: &OutputFormat, payload: &T) {
    match format {
        OutputFormat::Json => {
            let envelope = serde_json::json!({"ok": true, "data": payload});
            match serde_json::to_string_pretty(&envelope) {
                Ok(s) => println!("{s}"),
                Err(_) => println!(r#"{{"ok":true}}"#),
            }
        }
        OutputFormat::Text => {
            println!("{}", payload.render_text());
        }
    }
}

/// Write an error envelope to **stderr**.
///
/// The format is always JSON regardless of `--output`, so that callers can
/// reliably parse errors in scripts even when they requested text mode.
///
/// ```json
/// {"ok": false, "error": "ERROR_CODE", "message": "human readable"}
/// ```
pub fn print_error(err: &CliError) {
    let envelope = serde_json::json!({
        "ok": false,
        "error": err.error_code(),
        "message": err.to_string(),
    });
    match serde_json::to_string_pretty(&envelope) {
        Ok(s) => eprintln!("{s}"),
        Err(_) => eprintln!(r#"{{"ok":false,"error":"ERROR","message":"unknown error"}}"#),
    }
}

// ── helpers for command handlers ──────────────────────────────────────────────

/// Build a [`comfy_table::Table`] from headers and rows.
///
/// Convenience for command handlers that construct tables manually rather than
/// through the [`TextRow`] blanket impl.
pub fn build_table(headers: &[&str], rows: impl IntoIterator<Item = Vec<String>>) -> Table {
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(headers.iter().map(Cell::new));
    for row in rows {
        table.add_row(row.iter().map(Cell::new));
    }
    table
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::error::CliError;

    // ── JSON envelope helpers (test shape without I/O) ────────────────────────

    fn json_success<T: Serialize>(payload: &T) -> Value {
        serde_json::json!({"ok": true, "data": payload})
    }

    fn json_error(err: &CliError) -> Value {
        serde_json::json!({
            "ok": false,
            "error": err.error_code(),
            "message": err.to_string(),
        })
    }

    // ── success envelope ──────────────────────────────────────────────────────

    #[test]
    fn success_envelope_has_ok_true_and_data() {
        let env = json_success(&serde_json::json!({"agents": 3}));
        assert_eq!(env["ok"], true);
        assert_eq!(env["data"]["agents"], 3);
    }

    #[test]
    fn success_envelope_empty_list() {
        let empty: Vec<serde_json::Value> = vec![];
        let env = json_success(&empty);
        assert_eq!(env["ok"], true);
        assert!(env["data"].as_array().is_some_and(|a| a.is_empty()));
    }

    // ── error envelope ────────────────────────────────────────────────────────

    #[test]
    fn error_envelope_has_ok_false_and_code() {
        let err = CliError::AuthFailure("401".to_owned());
        let env = json_error(&err);
        assert_eq!(env["ok"], false);
        assert_eq!(env["error"], "AUTH_FAILURE");
        let msg = env["message"].as_str().unwrap_or("");
        assert!(msg.contains("auth failure"));
    }

    #[test]
    fn error_envelope_server_unreachable_uses_unreachable_code() {
        let err = CliError::ServerUnreachable("refused".to_owned());
        let env = json_error(&err);
        assert_eq!(env["error"], "UNREACHABLE");
    }

    #[test]
    fn error_envelope_not_found() {
        let err = CliError::NotFound("agent".to_owned());
        let env = json_error(&err);
        assert_eq!(env["error"], "NOT_FOUND");
    }

    #[test]
    fn error_envelope_timeout() {
        let err = CliError::Timeout("30s".to_owned());
        let env = json_error(&err);
        assert_eq!(env["error"], "TIMEOUT");
    }

    #[test]
    fn error_envelope_invalid_args() {
        let err = CliError::InvalidArgs("conflicting flags".to_owned());
        let env = json_error(&err);
        assert_eq!(env["error"], "INVALID_ARGS");
        assert_eq!(env["ok"], false);
    }

    #[test]
    fn error_envelope_server_error() {
        let err = CliError::ServerError("500".to_owned());
        let env = json_error(&err);
        assert_eq!(env["error"], "SERVER_ERROR");
        assert_eq!(env["ok"], false);
    }

    // ── TextRow / TextRender blanket impl ─────────────────────────────────────

    #[derive(Debug)]
    struct FakeItem {
        name: String,
        count: u32,
    }

    impl TextRow for FakeItem {
        fn headers() -> Vec<&'static str> {
            vec!["Name", "Count"]
        }

        fn row(&self) -> Vec<String> {
            vec![self.name.clone(), self.count.to_string()]
        }
    }

    #[test]
    fn text_render_empty_vec_returns_none_message() {
        let items: Vec<FakeItem> = vec![];
        assert_eq!(items.render_text(), "(none)");
    }

    #[test]
    fn text_render_non_empty_vec_includes_headers_and_values() {
        let items = vec![
            FakeItem { name: "alpha".to_owned(), count: 1 },
            FakeItem { name: "beta".to_owned(), count: 2 },
        ];
        let rendered = items.render_text();
        assert!(rendered.contains("Name"));
        assert!(rendered.contains("Count"));
        assert!(rendered.contains("alpha"));
        assert!(rendered.contains("beta"));
        assert!(rendered.contains('1'));
        assert!(rendered.contains('2'));
    }

    // ── build_table helper ────────────────────────────────────────────────────

    #[test]
    fn build_table_includes_provided_headers_and_rows() {
        let table = build_table(&["A", "B"], [vec!["x".to_owned(), "y".to_owned()]]);
        let rendered = table.to_string();
        assert!(rendered.contains('A'));
        assert!(rendered.contains('B'));
        assert!(rendered.contains('x'));
        assert!(rendered.contains('y'));
    }
}
