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
//! # Streaming JSON mode (`log tail --follow`)
//!
//! Streaming commands emit one compact JSON line per record (NDJSON).  Each
//! line uses the same envelope as regular responses so that machine consumers
//! need no special-casing:
//!
//! ```json
//! {"ok":true,"data":<entry-object>}
//! {"ok":true,"data":<entry-object>}
//! ```
//!
//! Serialisation failures in streaming mode write an error line to **stderr**
//! (same envelope as all other errors) and do not abort the stream.
//!
//! # Text mode (`--output text`)
//!
//! Types that implement [`TextRender`] control their own human-readable
//! representation.  List types use the [`TextRow`] blanket impl which builds
//! a [`comfy_table::Table`].  Streaming commands emit one text line per record.
//! Error format on stderr is always JSON regardless of mode.
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

use crate::error::{CliError, ERROR_CODE_SERIALIZE_FAILED};

// ── output format ─────────────────────────────────────────────────────────────

/// Output format selected via `--output`.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    /// Structured JSON (machine-readable, default).
    Json,
    /// Human-readable text tables.
    Text,
}

#[derive(Serialize)]
struct SuccessEnvelope<'a, T> {
    ok: bool,
    data: &'a T,
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
pub fn print_success<T: Serialize + TextRender>(
    format: &OutputFormat,
    payload: &T,
) -> Result<(), CliError> {
    write_success(&mut std::io::stdout(), format, payload)
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
    write_error(&mut std::io::stderr(), err);
}

/// Write a single streaming entry to stdout.
///
/// Used by long-running commands such as `log tail --follow` where one record
/// is emitted per server poll cycle rather than a single bulk response.
///
/// * **JSON mode** — emits a compact `{"ok": true, "data": <entry>}` line so
///   that streaming output uses the same envelope as every other command.
///   Serialisation failures are written as an error line to **stderr** and the
///   stream continues.
/// * **Text mode** — emits `text_line` verbatim followed by a newline.
pub fn print_stream_entry<T: Serialize>(format: &OutputFormat, entry: &T, text_line: &str) {
    write_stream_entry(&mut std::io::stdout(), &mut std::io::stderr(), format, entry, text_line);
}

// ── internal write helpers (accept any `Write` for testability) ───────────────

fn write_success<T: Serialize + TextRender, W: std::io::Write>(
    out: &mut W,
    format: &OutputFormat,
    payload: &T,
) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => {
            let envelope = SuccessEnvelope { ok: true, data: payload };
            let serialized = serde_json::to_string_pretty(&envelope).map_err(|e| {
                CliError::SerializeFailed(format!("failed to serialize response: {e}"))
            })?;
            let _ = writeln!(out, "{serialized}");
        }
        OutputFormat::Text => {
            let _ = writeln!(out, "{}", payload.render_text());
        }
    }

    Ok(())
}

fn write_error<W: std::io::Write>(out: &mut W, err: &CliError) {
    let envelope = serde_json::json!({
        "ok": false,
        "error": err.error_code(),
        "message": err.to_string(),
    });
    match serde_json::to_string_pretty(&envelope) {
        Ok(s) => {
            let _ = writeln!(out, "{s}");
        }
        Err(_) => {
            let _ = writeln!(out, r#"{{"ok":false,"error":"ERROR","message":"unknown error"}}"#);
        }
    }
}

pub(crate) fn write_stream_entry<T: Serialize, W: std::io::Write, E: std::io::Write>(
    out: &mut W,
    err_out: &mut E,
    format: &OutputFormat,
    entry: &T,
    text_line: &str,
) {
    match format {
        OutputFormat::Json => {
            let envelope = SuccessEnvelope { ok: true, data: entry };
            match serde_json::to_string(&envelope) {
                Ok(s) => {
                    let _ = writeln!(out, "{s}");
                }
                Err(e) => {
                    let err_envelope = serde_json::json!({
                        "ok": false,
                        "error": ERROR_CODE_SERIALIZE_FAILED,
                        "message": format!("failed to serialize stream entry: {e}"),
                    });
                    // Best-effort: if this serialisation also fails we have no
                    // further recourse.
                    if let Ok(s) = serde_json::to_string(&err_envelope) {
                        let _ = writeln!(err_out, "{s}");
                    }
                }
            }
        }
        OutputFormat::Text => {
            let _ = writeln!(out, "{text_line}");
        }
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

    #[test]
    fn build_table_zero_rows_does_not_panic_and_contains_headers() {
        let table = build_table(&["X", "Y"], std::iter::empty::<Vec<String>>());
        let rendered = table.to_string();
        assert!(rendered.contains('X'));
        assert!(rendered.contains('Y'));
    }

    // ── I/O side-effect tests via write_success / write_error ────────────────
    //
    // `print_success` and `print_error` are thin wrappers around the private
    // `write_success` / `write_error` helpers that accept any `io::Write`.
    // Testing through those helpers with a `Vec<u8>` buffer avoids the
    // Rust test-harness stdout capture that prevents fd-level tricks (like
    // the `gag` crate) from working reliably inside `cargo test`.

    /// Minimal payload that is both [`Serialize`] and [`TextRender`].
    #[derive(serde::Serialize)]
    struct FakePayload {
        value: String,
    }

    impl TextRender for FakePayload {
        fn render_text(&self) -> String {
            format!("rendered={}", self.value)
        }
    }

    #[test]
    fn write_success_json_mode_emits_ok_envelope() {
        let payload = FakePayload { value: "hello".to_owned() };
        let mut buf = Vec::new();
        write_success(&mut buf, &OutputFormat::Json, &payload).expect("success");

        let output = String::from_utf8(buf).expect("utf-8");
        let v: serde_json::Value =
            serde_json::from_str(output.trim()).expect("output is valid JSON");
        assert_eq!(v["ok"], true);
        assert_eq!(v["data"]["value"], "hello");
    }

    #[test]
    fn write_success_text_mode_invokes_render_text() {
        let payload = FakePayload { value: "world".to_owned() };
        let mut buf = Vec::new();
        write_success(&mut buf, &OutputFormat::Text, &payload).expect("success");

        let output = String::from_utf8(buf).expect("utf-8");
        assert!(output.contains("rendered=world"), "expected render_text output, got: {output:?}");
    }

    struct BrokenPayload;

    impl serde::Serialize for BrokenPayload {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("boom"))
        }
    }

    impl TextRender for BrokenPayload {
        fn render_text(&self) -> String {
            "broken".to_owned()
        }
    }

    #[test]
    fn write_success_json_mode_returns_error_on_serialization_failure() {
        let payload = BrokenPayload;
        let mut buf = Vec::new();
        let err = write_success(&mut buf, &OutputFormat::Json, &payload).expect_err("failure");

        assert!(buf.is_empty(), "serialization failure must not fabricate stdout output");
        assert_eq!(err.error_code(), ERROR_CODE_SERIALIZE_FAILED);
        assert!(err.to_string().contains("failed to serialize response"));
    }

    #[test]
    fn write_error_emits_ok_false_envelope_with_code_and_message() {
        let err = CliError::NotFound("agent-abc".to_owned());
        let mut buf = Vec::new();
        write_error(&mut buf, &err);

        let output = String::from_utf8(buf).expect("utf-8");
        let v: serde_json::Value =
            serde_json::from_str(output.trim()).expect("output is valid JSON");
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"], "NOT_FOUND");
        let msg = v["message"].as_str().unwrap_or("");
        assert!(msg.contains("agent-abc"), "message should include entity name");
    }

    // ── write_stream_entry ────────────────────────────────────────────────────

    #[test]
    fn write_stream_entry_json_mode_wraps_entry_in_ok_envelope() {
        let payload = FakePayload { value: "stream-item".to_owned() };
        let mut out = Vec::new();
        let mut err_out = Vec::new();
        write_stream_entry(&mut out, &mut err_out, &OutputFormat::Json, &payload, "ignored");

        let line = String::from_utf8(out).expect("utf-8");
        let v: serde_json::Value =
            serde_json::from_str(line.trim()).expect("single compact JSON line");
        assert_eq!(v["ok"], true);
        assert_eq!(v["data"]["value"], "stream-item");
        assert!(err_out.is_empty(), "no errors expected");
    }

    #[test]
    fn write_stream_entry_json_mode_emits_compact_json_not_pretty() {
        let payload = FakePayload { value: "compact".to_owned() };
        let mut out = Vec::new();
        let mut err_out = Vec::new();
        write_stream_entry(&mut out, &mut err_out, &OutputFormat::Json, &payload, "ignored");

        let line = String::from_utf8(out).expect("utf-8").trim().to_owned();
        // Compact serialisation has no embedded newlines.
        assert!(!line.contains('\n'), "stream entry must be a single line: {line:?}");
    }

    #[test]
    fn write_stream_entry_text_mode_emits_text_line_verbatim() {
        let payload = FakePayload { value: "irrelevant".to_owned() };
        let mut out = Vec::new();
        let mut err_out = Vec::new();
        write_stream_entry(&mut out, &mut err_out, &OutputFormat::Text, &payload, "my text line");

        let line = String::from_utf8(out).expect("utf-8");
        assert_eq!(line.trim(), "my text line");
        assert!(err_out.is_empty(), "no errors expected");
    }

    #[test]
    fn write_stream_entry_json_mode_multiple_calls_each_emit_one_line() {
        let mut out = Vec::new();
        let mut err_out = Vec::new();
        for i in 0..3u32 {
            let payload = serde_json::json!({"i": i});
            write_stream_entry(&mut out, &mut err_out, &OutputFormat::Json, &payload, "");
        }

        let output = String::from_utf8(out).expect("utf-8");
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 3, "one line per entry");
        for (i, line) in lines.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON per line");
            assert_eq!(v["ok"], true);
            assert_eq!(v["data"]["i"], i as u64);
        }
    }

    #[test]
    fn write_stream_entry_json_mode_serialization_failure_emits_structured_stderr() {
        let payload = BrokenPayload;
        let mut out = Vec::new();
        let mut err_out = Vec::new();
        write_stream_entry(&mut out, &mut err_out, &OutputFormat::Json, &payload, "ignored");

        assert!(out.is_empty(), "failed stream serialization must not emit stdout");
        let err = String::from_utf8(err_out).expect("utf-8");
        let v: serde_json::Value = serde_json::from_str(err.trim()).expect("stderr is valid JSON");
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"], ERROR_CODE_SERIALIZE_FAILED);
        assert!(
            v["message"].as_str().unwrap_or_default().contains("failed to serialize stream entry")
        );
    }
}
