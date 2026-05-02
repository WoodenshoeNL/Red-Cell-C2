//! `loot export` subcommand — CSV and JSONL export pipeline.

use tracing::instrument;

use crate::AgentId;
use crate::ExportFormat;
use crate::client::ApiClient;
use crate::error::CliError;

use super::list::list;
use super::types::{LootEntry, LootExportResult};

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
pub(super) async fn export(
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

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
                task_id: None,
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
                task_id: None,
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
