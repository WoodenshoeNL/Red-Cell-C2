//! `red-cell-cli loot` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `loot list [filters]` | `GET /api/v1/loot?...` | paginated, filterable |
//! | `loot download <id> --out <path>` | `GET /api/v1/loot/{id}` | save bytes to disk |

use std::io::Write as _;

use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::LootCommands;
use crate::client::ApiClient;
use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{OutputFormat, TextRender, TextRow, print_error, print_success};

// ── raw API response shapes ───────────────────────────────────────────────────

/// Mirrors the `LootSummary` struct returned by `GET /api/v1/loot`.
///
/// Additional fields sent by the server are silently ignored — no
/// `deny_unknown_fields` is set.
#[derive(Debug, Deserialize)]
struct RawLootSummary {
    id: i64,
    agent_id: String,
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
    pub agent_id: String,
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
            self.agent_id.clone(),
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
        LootCommands::List { kind, agent, operator, since, limit } => {
            match list(
                client,
                limit,
                since.as_deref(),
                kind.as_deref(),
                agent.as_deref(),
                operator.as_deref(),
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

        LootCommands::Download { id, out } => match download(client, id, &out).await {
            Ok(bytes) => {
                print_success(fmt, &LootDownloadResult { id, saved: out, bytes });
                EXIT_SUCCESS
            }
            Err(e) => {
                print_error(&e);
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
    agent_id: Option<&str>,
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
        params.push(format!("agent_id={}", percent_encode(aid)));
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

/// Percent-encode a query-parameter value.
///
/// Safe characters (RFC 3986 unreserved plus `:` for ISO 8601 timestamps)
/// are left unchanged; everything else is `%XX`-encoded.
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

    fn sample_raw() -> RawLootSummary {
        RawLootSummary {
            id: 42,
            agent_id: "DEADBEEF".to_owned(),
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
        assert_eq!(entry.agent_id, "DEADBEEF");
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

    #[test]
    fn percent_encode_leaves_safe_chars_unchanged() {
        assert_eq!(percent_encode("abc123-_.~:"), "abc123-_.~:");
    }

    #[test]
    fn percent_encode_encodes_space() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
    }

    #[test]
    fn percent_encode_iso8601_timestamp_unchanged() {
        assert_eq!(percent_encode("2026-01-01T12:00:00Z"), "2026-01-01T12:00:00Z");
    }
}
