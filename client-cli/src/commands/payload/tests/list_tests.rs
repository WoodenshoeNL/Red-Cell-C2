use super::super::types::{PayloadRow, RawPayloadSummary, payload_row_from_raw};
use crate::output::{TextRender, TextRow};

// ── PayloadRow ────────────────────────────────────────────────────────────────

#[test]
fn payload_row_headers_match_row_length() {
    let row = PayloadRow {
        id: "abc123".to_owned(),
        name: "demon_x64.exe".to_owned(),
        arch: "x86_64".to_owned(),
        format: "exe".to_owned(),
        built_at: "2026-03-21T00:00:00Z".to_owned(),
    };
    assert_eq!(PayloadRow::headers().len(), row.row().len());
}

#[test]
fn payload_row_serialises_all_fields() {
    let row = PayloadRow {
        id: "xyz".to_owned(),
        name: "demon.bin".to_owned(),
        arch: "aarch64".to_owned(),
        format: "bin".to_owned(),
        built_at: "2026-03-21T12:00:00Z".to_owned(),
    };
    let v = serde_json::to_value(&row).expect("serialise");
    assert_eq!(v["id"], "xyz");
    assert_eq!(v["arch"], "aarch64");
    assert_eq!(v["format"], "bin");
}

#[test]
fn vec_payload_row_renders_table_with_data() {
    let rows = vec![PayloadRow {
        id: "abc".to_owned(),
        name: "demon.exe".to_owned(),
        arch: "x86_64".to_owned(),
        format: "exe".to_owned(),
        built_at: "2026-03-21T00:00:00Z".to_owned(),
    }];
    let rendered = rows.render_text();
    assert!(rendered.contains("abc"));
    assert!(rendered.contains("x86_64"));
    assert!(rendered.contains("exe"));
}

#[test]
fn vec_payload_row_empty_renders_none() {
    let rows: Vec<PayloadRow> = vec![];
    assert_eq!(rows.render_text(), "(none)");
}

#[test]
fn payload_row_from_raw_maps_all_fields() {
    let raw = RawPayloadSummary {
        id: "id1".to_owned(),
        name: "n".to_owned(),
        arch: "x86_64".to_owned(),
        format: "dll".to_owned(),
        built_at: "2026-01-01T00:00:00Z".to_owned(),
    };
    let row = payload_row_from_raw(raw);
    assert_eq!(row.id, "id1");
    assert_eq!(row.format, "dll");
    assert_eq!(row.arch, "x86_64");
}
