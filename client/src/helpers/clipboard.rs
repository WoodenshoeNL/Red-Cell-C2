//! Clipboard and file-download wrappers: loot export (CSV/JSON), native save-file dialogs.

use std::path::Path;

use base64::Engine;
use rfd::FileDialog;

use super::format::{csv_field, json_str, loot_sub_category_label};
use crate::transport::LootItem;

// ── Download helpers ──────────────────────────────────────────────────────────

/// Result of attempting to save a completed file-browser download through the native dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompletedDownloadSaveOutcome {
    /// User cancelled the dialog or did not choose a path.
    Cancelled,
    /// Data was written to the path the user chose.
    Saved,
    /// The user chose a path but `std::fs::write` failed (permissions, disk full, etc.).
    WriteFailed(String),
}

/// Returns the suggested local file name for a completed remote path (sanitized).
pub(crate) fn suggested_file_name_for_completed_download(remote_path: &str) -> String {
    std::path::Path::new(remote_path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(sanitize_file_name)
        .unwrap_or_else(|| "download.bin".to_owned())
}

/// Opens a native save-file dialog for a completed file-browser download.
///
/// The suggested file name is derived from `remote_path`. If the user chooses a path,
/// bytes are written with [`std::fs::write`]. The dialog only selects the path; write
/// failures must be surfaced by the caller (for example via file-browser `status_message`).
pub(crate) fn save_completed_download(
    remote_path: &str,
    data: &[u8],
) -> CompletedDownloadSaveOutcome {
    let file_name = suggested_file_name_for_completed_download(remote_path);

    let Some(destination) = FileDialog::new().set_file_name(&file_name).save_file() else {
        return CompletedDownloadSaveOutcome::Cancelled;
    };

    if let Err(err) = std::fs::write(&destination, data) {
        return CompletedDownloadSaveOutcome::WriteFailed(format!(
            "Failed to save {}: {err}",
            destination.display()
        ));
    }

    CompletedDownloadSaveOutcome::Saved
}

pub(crate) fn download_loot_item(item: &LootItem) -> std::result::Result<String, String> {
    let Some(encoded) = &item.content_base64 else {
        return Err("This loot item does not include downloadable content.".to_owned());
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| format!("Failed to decode loot payload: {error}"))?;
    let file_name = derive_download_file_name(item);
    let output_dir = dirs::download_dir().unwrap_or_else(std::env::temp_dir);
    let output_path = next_available_path(&output_dir.join(file_name));
    std::fs::write(&output_path, bytes)
        .map_err(|error| format!("Failed to save loot file: {error}"))?;
    Ok(format!("Saved {}", output_path.display()))
}

pub(crate) fn derive_download_file_name(item: &LootItem) -> String {
    let candidate = item
        .file_path
        .as_deref()
        .and_then(|path| std::path::Path::new(path).file_name())
        .and_then(|value| value.to_str())
        .unwrap_or(item.name.as_str());
    sanitize_file_name(candidate)
}

pub(crate) fn sanitize_file_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|ch| match ch {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => ch,
        })
        .collect();
    if sanitized.trim().is_empty() { "loot.bin".to_owned() } else { sanitized }
}

pub(crate) fn next_available_path(path: &std::path::Path) -> std::path::PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }

    let stem = path.file_stem().and_then(|value| value.to_str()).unwrap_or("loot");
    let extension = path.extension().and_then(|value| value.to_str()).unwrap_or_default();
    for index in 1..1000 {
        let candidate = if extension.is_empty() {
            path.with_file_name(format!("{stem}-{index}"))
        } else {
            path.with_file_name(format!("{stem}-{index}.{extension}"))
        };
        if !candidate.exists() {
            return candidate;
        }
    }

    path.to_path_buf()
}

// ── Loot export ───────────────────────────────────────────────────────────────

/// Export loot items to CSV under `output_dir` (as `loot.csv`, or a suffixed name if needed).
pub(crate) fn export_loot_csv_to(
    items: &[&LootItem],
    output_dir: &Path,
) -> std::result::Result<String, String> {
    let mut out = String::from(
        "id,kind,sub_category,name,agent_id,source,collected_at,file_path,size_bytes,preview\n",
    );
    for item in items {
        let sub = loot_sub_category_label(item);
        out.push_str(&csv_field(item.id.map(|v| v.to_string()).as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(item.kind.label()));
        out.push(',');
        out.push_str(&csv_field(sub));
        out.push(',');
        out.push_str(&csv_field(&item.name));
        out.push(',');
        out.push_str(&csv_field(&item.agent_id));
        out.push(',');
        out.push_str(&csv_field(&item.source));
        out.push(',');
        out.push_str(&csv_field(&item.collected_at));
        out.push(',');
        out.push_str(&csv_field(item.file_path.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(item.size_bytes.map(|v| v.to_string()).as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(item.preview.as_deref().unwrap_or("")));
        out.push('\n');
    }
    let output_path = next_available_path(&output_dir.join("loot.csv"));
    std::fs::write(&output_path, out.as_bytes()).map_err(|e| format!("Failed to save CSV: {e}"))?;
    Ok(format!("Exported {} item(s) to {}", items.len(), output_path.display()))
}

/// Export loot items to CSV and save to the downloads directory.
pub(crate) fn export_loot_csv(items: &[&LootItem]) -> std::result::Result<String, String> {
    let output_dir = dirs::download_dir().unwrap_or_else(std::env::temp_dir);
    export_loot_csv_to(items, &output_dir)
}

/// Export loot items to JSON under `output_dir` (as `loot.json`, or a suffixed name if needed).
pub(crate) fn export_loot_json_to(
    items: &[&LootItem],
    output_dir: &Path,
) -> std::result::Result<String, String> {
    let mut out = String::from("[\n");
    for (index, item) in items.iter().enumerate() {
        let sub = loot_sub_category_label(item);
        out.push_str("  {");
        out.push_str(&format!("\"id\":{},", item.id.unwrap_or(0)));
        out.push_str(&format!("\"kind\":{},", json_str(item.kind.label())));
        out.push_str(&format!("\"sub_category\":{},", json_str(sub)));
        out.push_str(&format!("\"name\":{},", json_str(&item.name)));
        out.push_str(&format!("\"agent_id\":{},", json_str(&item.agent_id)));
        out.push_str(&format!("\"source\":{},", json_str(&item.source)));
        out.push_str(&format!("\"collected_at\":{},", json_str(&item.collected_at)));
        out.push_str(&format!(
            "\"file_path\":{},",
            item.file_path.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned())
        ));
        out.push_str(&format!(
            "\"size_bytes\":{},",
            item.size_bytes.map(|v| v.to_string()).unwrap_or_else(|| "null".to_owned())
        ));
        out.push_str(&format!(
            "\"preview\":{}",
            item.preview.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned())
        ));
        out.push('}');
        if index + 1 < items.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push(']');
    let output_path = next_available_path(&output_dir.join("loot.json"));
    std::fs::write(&output_path, out.as_bytes())
        .map_err(|e| format!("Failed to save JSON: {e}"))?;
    Ok(format!("Exported {} item(s) to {}", items.len(), output_path.display()))
}

/// Export loot items to JSON and save to the downloads directory.
pub(crate) fn export_loot_json(items: &[&LootItem]) -> std::result::Result<String, String> {
    let output_dir = dirs::download_dir().unwrap_or_else(std::env::temp_dir);
    export_loot_json_to(items, &output_dir)
}

#[cfg(test)]
mod completed_download_tests {
    use super::suggested_file_name_for_completed_download;

    #[test]
    fn suggested_file_name_uses_leaf_and_sanitizes() {
        assert_eq!(
            suggested_file_name_for_completed_download("/var/log/app/secrets:file?.txt"),
            "secrets_file_.txt"
        );
    }

    #[test]
    fn suggested_file_name_fallback_when_no_leaf() {
        assert_eq!(suggested_file_name_for_completed_download("/"), "download.bin");
    }
}
