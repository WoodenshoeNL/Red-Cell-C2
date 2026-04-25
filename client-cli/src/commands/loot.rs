//! `red-cell-cli loot` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `loot list [filters]` | `GET /api/v1/loot?...` | paginated, filterable |
//! | `loot download <id> --out <path>` | `GET /api/v1/loot/{id}` | save bytes to disk |
//! | `loot export --format csv\|jsonl` | `GET /api/v1/loot?...` | flat export; without `--file`, payload → stdout, metadata JSON → stderr |

use std::collections::HashSet;
use std::io::Write as _;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{instrument, warn};

use crate::AgentId;
use crate::ExportFormat;
use crate::LootCommands;
use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::defaults::{LOOT_LIST_WATCH_POLL_INTERVAL_SECS, RATE_LIMIT_DEFAULT_WAIT_SECS};
use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{
    OutputFormat, TextRender, TextRow, print_error, print_stream_entry, print_success,
    print_success_metadata_stderr,
};
use crate::util::percent_encode;

// ── raw API response shapes ───────────────────────────────────────────────────

/// Mirrors the `LootSummary` struct returned by `GET /api/v1/loot`.
///
/// Additional fields sent by the server are silently ignored — no
/// `deny_unknown_fields` is set.
#[derive(Debug, Deserialize)]
struct RawLootSummary {
    id: i64,
    agent_id: AgentId,
    kind: String,
    name: String,
    file_path: Option<String>,
    size_bytes: Option<i64>,
    captured_at: String,
    has_data: bool,
    operator: Option<String>,
}

/// Mirrors the `LootPage` wrapper returned by `GET /api/v1/loot`.
#[derive(Debug, Deserialize)]
struct RawLootPage {
    items: Vec<RawLootSummary>,
}

// ── public output types ───────────────────────────────────────────────────────

/// A single loot entry returned by `loot list`.
#[derive(Debug, Clone, Serialize)]
pub struct LootEntry {
    /// Numeric database identifier.
    pub id: i64,
    /// Agent that produced this loot item.
    pub agent_id: AgentId,
    /// Loot category (e.g. `"screenshot"`, `"credential"`, `"file"`).
    pub kind: String,
    /// Display name or filename of the loot item.
    pub name: String,
    /// Remote path on the agent where the file was captured, if applicable.
    pub file_path: Option<String>,
    /// Size of the stored binary data in bytes.
    pub size_bytes: Option<i64>,
    /// ISO 8601 UTC timestamp when the loot was captured.
    pub captured_at: String,
    /// Whether binary data is available for download.
    pub has_data: bool,
    /// Operator who triggered the capture, if known.
    pub operator: Option<String>,
}

impl TextRow for LootEntry {
    fn headers() -> Vec<&'static str> {
        vec!["ID", "Agent", "Kind", "Name", "Size", "Captured At", "Has Data"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.id.to_string(),
            self.agent_id.to_string(),
            self.kind.clone(),
            self.name.clone(),
            self.size_bytes.map(|s| s.to_string()).unwrap_or_default(),
            self.captured_at.clone(),
            self.has_data.to_string(),
        ]
    }
}

/// Result returned by `loot download`.
#[derive(Debug, Clone, Serialize)]
pub struct LootDownloadResult {
    /// Numeric loot identifier that was downloaded.
    pub id: i64,
    /// Local path the bytes were saved to.
    pub saved: String,
    /// Number of bytes written.
    pub bytes: usize,
}

impl TextRender for LootDownloadResult {
    fn render_text(&self) -> String {
        format!("Saved loot #{} → {} ({} bytes)", self.id, self.saved, self.bytes)
    }
}

// ── top-level dispatcher ──────────────────────────────────────────────────────

/// Dispatch a [`LootCommands`] variant and return a process exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: LootCommands) -> i32 {
    match action {
        LootCommands::List { kind, agent, operator, since, limit, watch, max_failures } => {
            if watch {
                watch_loot(
                    client,
                    fmt,
                    limit,
                    since.as_deref(),
                    kind.as_deref(),
                    agent,
                    operator.as_deref(),
                    max_failures,
                )
                .await
            } else {
                match list(
                    client,
                    limit,
                    since.as_deref(),
                    kind.as_deref(),
                    agent,
                    operator.as_deref(),
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
        }

        LootCommands::Download { id, out } => match download(client, id, &out).await {
            Ok(bytes) => match print_success(fmt, &LootDownloadResult { id, saved: out, bytes }) {
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

        LootCommands::Export { format, file, kind, agent, operator, since, limit } => match export(
            client,
            &format,
            file.as_deref(),
            limit,
            since.as_deref(),
            kind.as_deref(),
            agent,
            operator.as_deref(),
        )
        .await
        {
            Ok(result) => {
                // Raw CSV/JSONL is already on stdout; keep the JSON envelope off stdout (stderr only).
                let print = if result.destination == "stdout" {
                    print_success_metadata_stderr(fmt, &result)
                } else {
                    print_success(fmt, &result)
                };
                match print {
                    Ok(()) => EXIT_SUCCESS,
                    Err(e) => {
                        print_error(&e).ok();
                        e.exit_code()
                    }
                }
            }
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },
    }
}

// ── command implementations ───────────────────────────────────────────────────

/// `loot list` — fetch captured loot with optional filters.
///
/// # Examples
/// ```text
/// red-cell-cli loot list
/// red-cell-cli loot list --kind screenshot
/// red-cell-cli loot list --agent DEADBEEF --limit 20
/// ```
#[instrument(skip(client))]
async fn list(
    client: &ApiClient,
    limit: Option<u32>,
    since: Option<&str>,
    kind: Option<&str>,
    agent_id: Option<AgentId>,
    operator: Option<&str>,
) -> Result<Vec<LootEntry>, CliError> {
    let mut params: Vec<String> = Vec::new();

    if let Some(l) = limit {
        params.push(format!("limit={l}"));
    }
    if let Some(s) = since {
        params.push(format!("since={}", percent_encode(s)));
    }
    if let Some(k) = kind {
        params.push(format!("kind={}", percent_encode(k)));
    }
    if let Some(aid) = agent_id {
        params.push(format!("agent_id={}", percent_encode(&aid.to_string())));
    }
    if let Some(op) = operator {
        params.push(format!("operator={}", percent_encode(op)));
    }

    let path =
        if params.is_empty() { "/loot".to_owned() } else { format!("/loot?{}", params.join("&")) };
    let page: RawLootPage = client.get(&path).await?;
    Ok(page.items.into_iter().map(loot_entry_from_raw).collect())
}

/// `loot download <id> --out <path>` — download raw loot bytes to a local file.
///
/// # Examples
/// ```text
/// red-cell-cli loot download 42 --out ./screenshot.png
/// ```
#[instrument(skip(client))]
async fn download(client: &ApiClient, id: i64, out: &str) -> Result<usize, CliError> {
    let bytes = client.get_raw_bytes(&format!("/loot/{id}")).await?;
    let n = bytes.len();
    let mut file = std::fs::File::create(out)
        .map_err(|e| CliError::General(format!("cannot create output file {out:?}: {e}")))?;
    file.write_all(&bytes)
        .map_err(|e| CliError::General(format!("failed to write to {out:?}: {e}")))?;
    Ok(n)
}

// ── export ───────────────────────────────────────────────────────────────────

/// CSV column order — matches the `LootEntry` public fields.
const CSV_HEADERS: &[&str] = &[
    "id",
    "agent_id",
    "kind",
    "name",
    "file_path",
    "size_bytes",
    "captured_at",
    "has_data",
    "operator",
];

/// Result returned by `loot export`.
#[derive(Debug, Clone, Serialize)]
pub struct LootExportResult {
    /// Number of entries exported.
    pub entries: usize,
    /// Export format used.
    pub format: String,
    /// Output path, or "stdout" if written to stdout.
    pub destination: String,
}

impl TextRender for LootExportResult {
    fn render_text(&self) -> String {
        format!("Exported {} loot entries as {} → {}", self.entries, self.format, self.destination,)
    }
}

/// Write a single `LootEntry` as one CSV row.
fn write_csv_row(
    wtr: &mut csv::Writer<impl std::io::Write>,
    e: &LootEntry,
) -> Result<(), CliError> {
    wtr.write_record([
        &e.id.to_string(),
        &e.agent_id.to_string(),
        &e.kind,
        &e.name,
        e.file_path.as_deref().unwrap_or(""),
        &e.size_bytes.map(|s| s.to_string()).unwrap_or_default(),
        &e.captured_at,
        &e.has_data.to_string(),
        e.operator.as_deref().unwrap_or(""),
    ])
    .map_err(|err| CliError::General(format!("CSV write error: {err}")))?;
    Ok(())
}

/// `loot export` — export loot entries as CSV or JSONL.
#[instrument(skip(client, since, kind, operator))]
async fn export(
    client: &ApiClient,
    format: &ExportFormat,
    output: Option<&str>,
    limit: Option<u32>,
    since: Option<&str>,
    kind: Option<&str>,
    agent_id: Option<AgentId>,
    operator: Option<&str>,
) -> Result<LootExportResult, CliError> {
    let entries = list(client, limit, since, kind, agent_id, operator).await?;

    let destination = output.unwrap_or("stdout").to_owned();
    let format_name = match format {
        ExportFormat::Csv => "csv",
        ExportFormat::Jsonl => "jsonl",
    };

    match output {
        Some(path) => {
            let file = std::fs::File::create(path).map_err(|e| {
                CliError::General(format!("cannot create output file {path:?}: {e}"))
            })?;
            write_export(format, &entries, file)?;
        }
        None => {
            let stdout = std::io::stdout().lock();
            write_export(format, &entries, stdout)?;
        }
    }

    Ok(LootExportResult { entries: entries.len(), format: format_name.to_owned(), destination })
}

/// Serialize `entries` into the requested format, writing to `writer`.
fn write_export(
    format: &ExportFormat,
    entries: &[LootEntry],
    writer: impl std::io::Write,
) -> Result<(), CliError> {
    match format {
        ExportFormat::Csv => write_csv(entries, writer),
        ExportFormat::Jsonl => write_jsonl(entries, writer),
    }
}

/// Write entries as CSV with a header row.
fn write_csv(entries: &[LootEntry], writer: impl std::io::Write) -> Result<(), CliError> {
    let mut wtr = csv::Writer::from_writer(writer);
    wtr.write_record(CSV_HEADERS)
        .map_err(|e| CliError::General(format!("CSV header write error: {e}")))?;
    for entry in entries {
        write_csv_row(&mut wtr, entry)?;
    }
    wtr.flush().map_err(|e| CliError::General(format!("CSV flush error: {e}")))?;
    Ok(())
}

/// Write entries as JSONL (one JSON object per line).
fn write_jsonl(entries: &[LootEntry], mut writer: impl std::io::Write) -> Result<(), CliError> {
    for entry in entries {
        serde_json::to_writer(&mut writer, entry)
            .map_err(|e| CliError::General(format!("JSONL serialization error: {e}")))?;
        writer
            .write_all(b"\n")
            .map_err(|e| CliError::General(format!("JSONL write error: {e}")))?;
    }
    writer.flush().map_err(|e| CliError::General(format!("JSONL flush error: {e}")))?;
    Ok(())
}

// ── watch helpers ────────────────────────────────────────────────────────────

fn watch_timeout_exhausted(max_failures: u32, last_detail: &str) -> CliError {
    CliError::Timeout(format!(
        "loot list --watch: reached {max_failures} consecutive request timeouts (last: {last_detail})"
    ))
}

fn render_loot_stream_text(entry: &LootEntry) -> String {
    format!(
        "[loot #{}]  {}  {}  agent={}  {}",
        entry.id, entry.kind, entry.name, entry.agent_id, entry.captured_at,
    )
}

/// Follow-mode state for loot entries.
///
/// Tracks seen entry IDs at the cursor timestamp to deduplicate inclusive
/// `since` results — same pattern as `audit::follow::FollowCursor`.
#[derive(Debug, Default)]
struct LootFollowCursor {
    since: Option<String>,
    seen_ids: HashSet<i64>,
}

impl LootFollowCursor {
    fn from_entries(entries: &[LootEntry]) -> Self {
        if entries.is_empty() {
            return Self::default();
        }
        let latest_ts = entries.iter().map(|e| e.captured_at.as_str()).max().map(str::to_owned);
        let seen_ids = entries
            .iter()
            .filter(|e| Some(e.captured_at.as_str()) == latest_ts.as_deref())
            .map(|e| e.id)
            .collect();
        Self { since: latest_ts, seen_ids }
    }

    fn since(&self) -> Option<&str> {
        self.since.as_deref()
    }

    fn drain_new_entries<'a>(&mut self, entries: &'a [LootEntry]) -> Vec<&'a LootEntry> {
        let fresh: Vec<&LootEntry> = entries
            .iter()
            .filter(|e| match self.since.as_deref() {
                None => true,
                Some(cursor) if e.captured_at.as_str() > cursor => true,
                Some(cursor) if e.captured_at.as_str() == cursor => !self.seen_ids.contains(&e.id),
                _ => false,
            })
            .collect();

        if let Some(latest_ts) = fresh.iter().map(|e| e.captured_at.as_str()).max() {
            if self.since.as_deref() != Some(latest_ts) {
                self.since = Some(latest_ts.to_owned());
                self.seen_ids.clear();
            }
            for e in fresh.iter().filter(|e| e.captured_at.as_str() == latest_ts) {
                self.seen_ids.insert(e.id);
            }
        }

        fresh
    }
}

/// `loot list --watch` — print the initial entries then stream new ones.
#[instrument(
    skip(client, fmt, since, kind, operator),
    fields(max_failures = max_failures)
)]
async fn watch_loot(
    client: &ApiClient,
    fmt: &OutputFormat,
    limit: Option<u32>,
    since: Option<&str>,
    kind: Option<&str>,
    agent_id: Option<AgentId>,
    operator: Option<&str>,
    max_failures: u32,
) -> i32 {
    let mut backoff = Backoff::with_initial_delay(LOOT_LIST_WATCH_POLL_INTERVAL_SECS);
    let mut consecutive_timeouts = 0u32;

    let initial = loop {
        let result = tokio::select! {
            r = list(client, limit, since, kind, agent_id, operator) => r,
            _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
        };
        match result {
            Ok(entries) => break entries,
            Err(CliError::Timeout(msg)) => {
                consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                warn!(
                    attempt = consecutive_timeouts,
                    max_failures,
                    error = %msg,
                    "loot list --watch: timed out fetching initial snapshot; retrying"
                );
                if consecutive_timeouts >= max_failures {
                    let err = watch_timeout_exhausted(max_failures, &msg);
                    print_error(&err).ok();
                    return err.exit_code();
                }
                backoff.record_empty();
                tokio::select! {
                    _ = sleep(backoff.delay()) => {}
                    _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
                }
            }
            Err(e) => {
                print_error(&e).ok();
                return e.exit_code();
            }
        }
    };

    consecutive_timeouts = 0;

    if let Err(e) = print_success(fmt, &initial) {
        print_error(&e).ok();
        return e.exit_code();
    }

    let mut cursor = LootFollowCursor::from_entries(&initial);

    loop {
        let poll_result = tokio::select! {
            r = list(client, None, cursor.since(), kind, agent_id, operator) => r,
            _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
        };

        let sleep_duration = match poll_result {
            Err(CliError::RateLimited { retry_after_secs }) => {
                consecutive_timeouts = 0;
                Duration::from_secs(retry_after_secs.unwrap_or(RATE_LIMIT_DEFAULT_WAIT_SECS))
            }
            Err(CliError::Timeout(msg)) => {
                consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                warn!(
                    attempt = consecutive_timeouts,
                    max_failures,
                    error = %msg,
                    "loot list --watch: timed out; retrying"
                );
                if consecutive_timeouts >= max_failures {
                    let err = watch_timeout_exhausted(max_failures, &msg);
                    print_error(&err).ok();
                    return err.exit_code();
                }
                backoff.record_empty();
                backoff.delay()
            }
            Err(e) => {
                print_error(&e).ok();
                return e.exit_code();
            }
            Ok(entries) => {
                consecutive_timeouts = 0;
                let fresh = cursor.drain_new_entries(&entries);
                if fresh.is_empty() {
                    backoff.record_empty();
                } else {
                    backoff.record_non_empty();
                    for entry in &fresh {
                        if let Err(e) =
                            print_stream_entry(fmt, *entry, &render_loot_stream_text(entry))
                        {
                            print_error(&e).ok();
                            return e.exit_code();
                        }
                    }
                }
                backoff.delay()
            }
        };

        tokio::select! {
            _ = sleep(sleep_duration) => {}
            _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn loot_entry_from_raw(raw: RawLootSummary) -> LootEntry {
    LootEntry {
        id: raw.id,
        agent_id: raw.agent_id,
        kind: raw.kind,
        name: raw.name,
        file_path: raw.file_path,
        size_bytes: raw.size_bytes,
        captured_at: raw.captured_at,
        has_data: raw.has_data,
        operator: raw.operator,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_raw() -> RawLootSummary {
        RawLootSummary {
            id: 42,
            agent_id: AgentId::new(0xDEADBEEF),
            kind: "screenshot".to_owned(),
            name: "Desktop_01.01.2026-12.00.00.png".to_owned(),
            file_path: None,
            size_bytes: Some(102400),
            captured_at: "2026-01-01T12:00:00Z".to_owned(),
            has_data: true,
            operator: Some("alice".to_owned()),
        }
    }

    #[test]
    fn loot_entry_from_raw_maps_all_fields() {
        let raw = sample_raw();
        let entry = loot_entry_from_raw(raw);
        assert_eq!(entry.id, 42);
        assert_eq!(entry.agent_id, AgentId::new(0xDEADBEEF));
        assert_eq!(entry.kind, "screenshot");
        assert_eq!(entry.name, "Desktop_01.01.2026-12.00.00.png");
        assert!(entry.file_path.is_none());
        assert_eq!(entry.size_bytes, Some(102400));
        assert_eq!(entry.captured_at, "2026-01-01T12:00:00Z");
        assert!(entry.has_data);
        assert_eq!(entry.operator.as_deref(), Some("alice"));
    }

    #[test]
    fn loot_entry_headers_match_row_length() {
        let entry = loot_entry_from_raw(sample_raw());
        assert_eq!(LootEntry::headers().len(), entry.row().len());
    }

    #[test]
    fn loot_entry_row_uses_empty_string_for_none_size() {
        let mut raw = sample_raw();
        raw.size_bytes = None;
        let entry = loot_entry_from_raw(raw);
        let row = entry.row();
        // 4th column (index 4) is size
        assert_eq!(row[4], "");
    }

    #[test]
    fn loot_entry_serialises_expected_fields() {
        let entry = loot_entry_from_raw(sample_raw());
        let v = serde_json::to_value(&entry).expect("serialise");
        assert_eq!(v["id"], 42);
        assert_eq!(v["kind"], "screenshot");
        assert_eq!(v["has_data"], true);
    }

    #[test]
    fn vec_loot_entry_renders_table_with_data() {
        let entries = vec![loot_entry_from_raw(sample_raw())];
        let rendered = entries.render_text();
        assert!(rendered.contains("DEADBEEF"));
        assert!(rendered.contains("screenshot"));
    }

    #[test]
    fn vec_loot_entry_empty_renders_none() {
        let entries: Vec<LootEntry> = vec![];
        assert_eq!(entries.render_text(), "(none)");
    }

    // ── loot follow cursor tests ─────────────────────────────────────────────

    fn sample_loot_entry(id: i64, captured_at: &str) -> LootEntry {
        LootEntry {
            id,
            agent_id: AgentId::new(0xDEAD),
            kind: "screenshot".to_owned(),
            name: format!("item_{id}"),
            file_path: None,
            size_bytes: Some(1024),
            captured_at: captured_at.to_owned(),
            has_data: true,
            operator: None,
        }
    }

    #[test]
    fn loot_cursor_from_empty_entries() {
        let cursor = LootFollowCursor::from_entries(&[]);
        assert!(cursor.since().is_none());
        assert!(cursor.seen_ids.is_empty());
    }

    #[test]
    fn loot_cursor_from_entries_uses_max_timestamp() {
        let entries = vec![
            sample_loot_entry(1, "2026-01-01T12:00:00Z"),
            sample_loot_entry(2, "2026-01-01T13:00:00Z"),
            sample_loot_entry(3, "2026-01-01T12:30:00Z"),
        ];
        let cursor = LootFollowCursor::from_entries(&entries);
        assert_eq!(cursor.since(), Some("2026-01-01T13:00:00Z"));
        assert!(cursor.seen_ids.contains(&2));
        assert_eq!(cursor.seen_ids.len(), 1);
    }

    #[test]
    fn loot_cursor_deduplicates_same_timestamp_entries() {
        let entries = vec![
            sample_loot_entry(1, "2026-01-01T12:00:00Z"),
            sample_loot_entry(2, "2026-01-01T12:00:00Z"),
        ];
        let cursor = LootFollowCursor::from_entries(&entries);
        assert_eq!(cursor.since(), Some("2026-01-01T12:00:00Z"));
        assert_eq!(cursor.seen_ids.len(), 2);
    }

    #[test]
    fn loot_cursor_drain_new_detects_new_entries() {
        let initial = vec![
            sample_loot_entry(1, "2026-01-01T12:00:00Z"),
            sample_loot_entry(2, "2026-01-01T12:00:00Z"),
        ];
        let mut cursor = LootFollowCursor::from_entries(&initial);

        let poll = vec![
            sample_loot_entry(3, "2026-01-01T13:00:00Z"),
            sample_loot_entry(2, "2026-01-01T12:00:00Z"),
            sample_loot_entry(1, "2026-01-01T12:00:00Z"),
        ];
        let fresh = cursor.drain_new_entries(&poll);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].id, 3);
        assert_eq!(cursor.since(), Some("2026-01-01T13:00:00Z"));
    }

    #[test]
    fn loot_cursor_drain_no_new_returns_empty() {
        let initial = vec![sample_loot_entry(1, "2026-01-01T12:00:00Z")];
        let mut cursor = LootFollowCursor::from_entries(&initial);
        let poll = vec![sample_loot_entry(1, "2026-01-01T12:00:00Z")];
        let fresh = cursor.drain_new_entries(&poll);
        assert!(fresh.is_empty());
    }

    #[test]
    fn loot_cursor_drain_new_at_same_timestamp_different_id() {
        let initial = vec![sample_loot_entry(1, "2026-01-01T12:00:00Z")];
        let mut cursor = LootFollowCursor::from_entries(&initial);
        let poll = vec![
            sample_loot_entry(2, "2026-01-01T12:00:00Z"),
            sample_loot_entry(1, "2026-01-01T12:00:00Z"),
        ];
        let fresh = cursor.drain_new_entries(&poll);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].id, 2);
    }

    #[test]
    fn render_loot_stream_text_contains_key_fields() {
        let entry = sample_loot_entry(42, "2026-01-01T12:00:00Z");
        let text = render_loot_stream_text(&entry);
        assert!(text.contains("42"));
        assert!(text.contains("screenshot"));
        assert!(text.contains("0000DEAD"));
    }

    #[test]
    fn watch_timeout_exhausted_is_timeout_error() {
        let err = watch_timeout_exhausted(3, "connection refused");
        assert!(matches!(err, CliError::Timeout(_)));
        assert_eq!(err.exit_code(), crate::error::EXIT_TIMEOUT);
        let msg = err.to_string();
        assert!(msg.contains('3'));
        assert!(msg.contains("connection refused"));
    }

    // ── export tests ─────────────────────────────────────────────────────────

    fn sample_entries() -> Vec<LootEntry> {
        vec![
            LootEntry {
                id: 1,
                agent_id: AgentId::new(0xDEADBEEF),
                kind: "screenshot".to_owned(),
                name: "Desktop.png".to_owned(),
                file_path: Some("/tmp/Desktop.png".to_owned()),
                size_bytes: Some(102400),
                captured_at: "2026-01-01T12:00:00Z".to_owned(),
                has_data: true,
                operator: Some("alice".to_owned()),
            },
            LootEntry {
                id: 2,
                agent_id: AgentId::new(0xCAFEBABE),
                kind: "credential".to_owned(),
                name: "creds.txt".to_owned(),
                file_path: None,
                size_bytes: None,
                captured_at: "2026-01-02T08:30:00Z".to_owned(),
                has_data: false,
                operator: None,
            },
        ]
    }

    #[test]
    fn write_csv_produces_header_and_rows() {
        let entries = sample_entries();
        let mut buf = Vec::new();
        write_csv(&entries, &mut buf).expect("write_csv");
        let text = String::from_utf8(buf).expect("utf8");
        let mut reader = csv::ReaderBuilder::new().from_reader(text.as_bytes());
        let headers = reader.headers().expect("headers").clone();
        assert_eq!(headers.len(), CSV_HEADERS.len());
        for (i, expected) in CSV_HEADERS.iter().enumerate() {
            assert_eq!(&headers[i], *expected);
        }
        let rows: Vec<csv::StringRecord> = reader.records().map(|r| r.expect("row")).collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(&rows[0][0], "1");
        assert_eq!(&rows[0][2], "screenshot");
        assert_eq!(&rows[1][0], "2");
        assert_eq!(&rows[1][2], "credential");
    }

    #[test]
    fn write_csv_empty_entries_produces_header_only() {
        let mut buf = Vec::new();
        write_csv(&[], &mut buf).expect("write_csv");
        let text = String::from_utf8(buf).expect("utf8");
        let mut reader = csv::ReaderBuilder::new().from_reader(text.as_bytes());
        let headers = reader.headers().expect("headers").clone();
        assert_eq!(headers.len(), CSV_HEADERS.len());
        let rows: Vec<csv::StringRecord> = reader.records().map(|r| r.expect("row")).collect();
        assert!(rows.is_empty());
    }

    #[test]
    fn write_csv_none_fields_become_empty_strings() {
        let entries = vec![LootEntry {
            id: 3,
            agent_id: AgentId::new(0x1234),
            kind: "file".to_owned(),
            name: "data.bin".to_owned(),
            file_path: None,
            size_bytes: None,
            captured_at: "2026-06-01T00:00:00Z".to_owned(),
            has_data: true,
            operator: None,
        }];
        let mut buf = Vec::new();
        write_csv(&entries, &mut buf).expect("write_csv");
        let text = String::from_utf8(buf).expect("utf8");
        let mut reader = csv::ReaderBuilder::new().from_reader(text.as_bytes());
        let row = reader.records().next().expect("row").expect("parse");
        // file_path (index 4) and size_bytes (index 5) and operator (index 8)
        assert_eq!(&row[4], "");
        assert_eq!(&row[5], "");
        assert_eq!(&row[8], "");
    }

    #[test]
    fn write_csv_required_columns_present() {
        let required: HashSet<&str> =
            ["id", "agent_id", "kind", "name", "captured_at"].into_iter().collect();
        let mut buf = Vec::new();
        write_csv(&sample_entries(), &mut buf).expect("write_csv");
        let text = String::from_utf8(buf).expect("utf8");
        let mut reader = csv::ReaderBuilder::new().from_reader(text.as_bytes());
        let headers: HashSet<&str> = reader.headers().expect("headers").iter().collect();
        for col in &required {
            assert!(headers.contains(col), "missing required column: {col}");
        }
    }

    #[test]
    fn write_jsonl_produces_one_line_per_entry() {
        let entries = sample_entries();
        let mut buf = Vec::new();
        write_jsonl(&entries, &mut buf).expect("write_jsonl");
        let text = String::from_utf8(buf).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let v0: serde_json::Value = serde_json::from_str(lines[0]).expect("parse line 0");
        assert_eq!(v0["id"], 1);
        assert_eq!(v0["kind"], "screenshot");
        let v1: serde_json::Value = serde_json::from_str(lines[1]).expect("parse line 1");
        assert_eq!(v1["id"], 2);
        assert_eq!(v1["kind"], "credential");
    }

    #[test]
    fn write_jsonl_empty_entries_produces_empty_output() {
        let mut buf = Vec::new();
        write_jsonl(&[], &mut buf).expect("write_jsonl");
        assert!(buf.is_empty());
    }

    #[test]
    fn write_jsonl_each_line_is_valid_json() {
        let entries = sample_entries();
        let mut buf = Vec::new();
        write_jsonl(&entries, &mut buf).expect("write_jsonl");
        let text = String::from_utf8(buf).expect("utf8");
        for line in text.lines() {
            serde_json::from_str::<serde_json::Value>(line)
                .expect("each JSONL line must be valid JSON");
        }
    }

    #[test]
    fn export_result_renders_text() {
        let result = LootExportResult {
            entries: 5,
            format: "csv".to_owned(),
            destination: "loot.csv".to_owned(),
        };
        let text = result.render_text();
        assert!(text.contains("5"));
        assert!(text.contains("csv"));
        assert!(text.contains("loot.csv"));
    }

    #[test]
    fn csv_headers_count_matches_csv_row_field_count() {
        let entries = sample_entries();
        let mut buf = Vec::new();
        write_csv(&entries, &mut buf).expect("write_csv");
        let text = String::from_utf8(buf).expect("utf8");
        let mut reader = csv::ReaderBuilder::new().from_reader(text.as_bytes());
        let header_count = reader.headers().expect("headers").len();
        for record in reader.records() {
            let row = record.expect("row");
            assert_eq!(row.len(), header_count);
        }
    }
}
