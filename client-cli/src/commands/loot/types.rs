//! Types shared across loot subcommands.

use serde::{Deserialize, Serialize};

use crate::AgentId;
use crate::output::{TextRender, TextRow};

// ── raw API response shapes ─────────────────────────────────────────────────

/// Mirrors the `LootSummary` struct returned by `GET /api/v1/loot`.
///
/// Additional fields sent by the server are silently ignored — no
/// `deny_unknown_fields` is set.
#[derive(Debug, Deserialize)]
pub(super) struct RawLootSummary {
    pub id: i64,
    pub agent_id: AgentId,
    pub kind: String,
    pub name: String,
    pub file_path: Option<String>,
    pub size_bytes: Option<i64>,
    pub captured_at: String,
    pub has_data: bool,
    pub operator: Option<String>,
}

/// Mirrors the `LootPage` wrapper returned by `GET /api/v1/loot`.
#[derive(Debug, Deserialize)]
pub(super) struct RawLootPage {
    pub items: Vec<RawLootSummary>,
}

// ── public output types ─────────────────────────────────────────────────────

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

/// Convert a raw API summary into a public [`LootEntry`].
pub(super) fn loot_entry_from_raw(raw: RawLootSummary) -> LootEntry {
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
}
