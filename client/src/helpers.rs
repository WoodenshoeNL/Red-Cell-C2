//! Pure helper functions shared across panel modules.
//!
//! These are stateless, standalone functions used by both the panel render
//! implementations and the task builder modules.  They carry no UI side-effects
//! on their own — they format data, filter slices, or perform simple file I/O.

use std::path::Path;

use base64::Engine;
use eframe::egui::{self, Color32, RichText};
use rfd::FileDialog;

use crate::python::{ScriptLoadStatus, ScriptOutputStream};
use crate::transport::{
    AgentFileBrowserState, AgentSummary, ConnectedOperatorState, FileBrowserEntry, LootItem,
    LootKind, ProcessEntry,
};
use crate::{
    CredentialSortColumn, CredentialSubFilter, FileSubFilter, LootPanelState, LootTypeFilter,
};

// ── Operator / role badge ────────────────────────────────────────────────────

pub(crate) fn role_badge_color(role: Option<&str>) -> Color32 {
    match role.map(|r| r.to_ascii_lowercase()).as_deref() {
        Some("admin") => Color32::from_rgb(220, 80, 60),
        Some("operator") => Color32::from_rgb(60, 130, 220),
        Some("readonly") | Some("read-only") | Some("analyst") => Color32::from_rgb(100, 180, 100),
        _ => Color32::from_rgb(140, 140, 140),
    }
}

/// Renders a small coloured role badge inline.
#[allow(dead_code)]
pub(crate) fn role_badge(ui: &mut egui::Ui, role: Option<&str>) {
    let label = role.unwrap_or("unassigned");
    let color = role_badge_color(role);
    let text = RichText::new(label).color(Color32::WHITE).small().strong();
    let frame = egui::Frame::new()
        .fill(color)
        .inner_margin(egui::Margin::symmetric(4, 2))
        .corner_radius(egui::CornerRadius::same(4));
    frame.show(ui, |ui| {
        ui.label(text);
    });
}

/// Renders a single operator entry in the connected-operators list.
#[allow(dead_code)]
pub(crate) fn render_operator_entry(
    ui: &mut egui::Ui,
    username: &str,
    op: &ConnectedOperatorState,
) {
    egui::Frame::new().inner_margin(egui::Margin::symmetric(0, 2)).show(ui, |ui| {
        ui.horizontal(|ui| {
            let status_color = if op.online {
                Color32::from_rgb(80, 200, 120)
            } else {
                Color32::from_rgb(160, 160, 160)
            };
            ui.colored_label(status_color, "●");
            ui.strong(username);
            role_badge(ui, op.role.as_deref());
        });
        if let Some(ts) = &op.last_seen {
            ui.label(RichText::new(format!("last seen: {ts}")).small().weak());
        }
        if !op.recent_commands.is_empty() {
            ui.label(RichText::new("Recent commands:").small().italics());
            for cmd in op.recent_commands.iter().take(5) {
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(format!(
                            "[{}] {} — {}",
                            cmd.agent_id, cmd.command_line, cmd.timestamp
                        ))
                        .small()
                        .weak(),
                    );
                });
            }
        }
    });
}

// ── Script helpers ───────────────────────────────────────────────────────────

pub(crate) fn script_status_label(status: ScriptLoadStatus) -> &'static str {
    match status {
        ScriptLoadStatus::Loaded => "loaded",
        ScriptLoadStatus::Error => "error",
        ScriptLoadStatus::Unloaded => "unloaded",
    }
}

pub(crate) fn script_status_color(status: ScriptLoadStatus) -> Color32 {
    match status {
        ScriptLoadStatus::Loaded => Color32::from_rgb(110, 199, 141),
        ScriptLoadStatus::Error => Color32::from_rgb(215, 83, 83),
        ScriptLoadStatus::Unloaded => Color32::from_rgb(232, 182, 83),
    }
}

pub(crate) fn script_output_label(stream: ScriptOutputStream) -> &'static str {
    match stream {
        ScriptOutputStream::Stdout => "stdout",
        ScriptOutputStream::Stderr => "stderr",
    }
}

pub(crate) fn script_output_color(stream: ScriptOutputStream) -> Color32 {
    match stream {
        ScriptOutputStream::Stdout => Color32::from_rgb(110, 199, 141),
        ScriptOutputStream::Stderr => Color32::from_rgb(215, 83, 83),
    }
}

pub(crate) fn script_name_for_display(path: &Path) -> Option<String> {
    path.file_stem().and_then(|stem| stem.to_str()).map(str::to_owned)
}

// ── Agent helpers ─────────────────────────────────────────────────────────────
// Note: agent_ip, agent_sleep_jitter, agent_matches_filter, sort_agents, and
// sort_button_label are defined in panels/agents.rs.  Only the helpers that are
// imported by OTHER panel modules (e.g. console.rs) live here.

pub(crate) fn agent_arch(agent: &AgentSummary) -> String {
    if agent.process_arch.trim().is_empty() {
        agent.os_arch.clone()
    } else {
        agent.process_arch.clone()
    }
}

pub(crate) fn agent_os(agent: &AgentSummary) -> String {
    if agent.os_build.trim().is_empty() {
        agent.os_version.clone()
    } else {
        format!("{} ({})", agent.os_version, agent.os_build)
    }
}

pub(crate) fn ellipsize(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }

    let mut output = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index + 1 >= max_chars {
            break;
        }
        output.push(ch);
    }
    output.push_str("...");
    output
}

// ── Process helpers ───────────────────────────────────────────────────────────

pub(crate) fn filtered_process_rows<'a>(
    rows: &'a [ProcessEntry],
    filter: &str,
) -> Vec<&'a ProcessEntry> {
    let trimmed = filter.trim();
    if trimmed.is_empty() {
        return rows.iter().collect();
    }

    let needle = trimmed.to_ascii_lowercase();
    rows.iter()
        .filter(|row| {
            row.name.to_ascii_lowercase().contains(&needle) || row.pid.to_string().contains(&needle)
        })
        .collect()
}

pub(crate) fn normalized_process_arch(arch: &str) -> String {
    match arch.trim().to_ascii_lowercase().as_str() {
        "x86" | "386" | "i386" => "x86".to_owned(),
        _ => "x64".to_owned(),
    }
}

// ── Loot helpers ──────────────────────────────────────────────────────────────

pub(crate) fn build_filtered_loot_indices(
    loot: &[LootItem],
    type_filter: LootTypeFilter,
    cred_filter: CredentialSubFilter,
    file_filter: FileSubFilter,
    agent_filter: &str,
    since_filter: &str,
    until_filter: &str,
    text_filter: &str,
) -> Vec<usize> {
    loot.iter()
        .enumerate()
        .filter_map(|(index, item)| {
            loot_matches_filters(
                item,
                type_filter,
                cred_filter,
                file_filter,
                agent_filter,
                since_filter,
                until_filter,
                text_filter,
            )
            .then_some(index)
        })
        .collect()
}

pub(crate) fn loot_table_row_height(ui: &egui::Ui) -> f32 {
    ui.text_style_height(&egui::TextStyle::Body) + 6.0
}

pub(crate) fn render_loot_credential_header(
    ui: &mut egui::Ui,
    panel: &mut LootPanelState,
    header_color: Color32,
) {
    egui::Grid::new("loot-cred-table-header")
        .num_columns(6)
        .striped(false)
        .min_col_width(60.0)
        .spacing([8.0, 2.0])
        .show(ui, |ui| {
            let columns = [
                (CredentialSortColumn::Name, "Name"),
                (CredentialSortColumn::Category, "Type"),
                (CredentialSortColumn::Agent, "Agent"),
                (CredentialSortColumn::Source, "Source"),
                (CredentialSortColumn::Time, "Collected"),
            ];
            for (col, label) in columns {
                let active = panel.cred_sort_column == col;
                let arrow =
                    if active { if panel.cred_sort_desc { " v" } else { " ^" } } else { "" };
                let text = RichText::new(format!("{label}{arrow}")).strong().color(header_color);
                if ui.label(text).clicked() {
                    if panel.cred_sort_column == col {
                        panel.cred_sort_desc = !panel.cred_sort_desc;
                    } else {
                        panel.cred_sort_column = col;
                        panel.cred_sort_desc = false;
                    }
                }
            }
            ui.label(RichText::new("Value / Preview").strong().color(header_color));
            ui.end_row();
        });
}

pub(crate) fn render_loot_credential_row(ui: &mut egui::Ui, item: &LootItem) {
    ui.label(&item.name);
    ui.label(
        RichText::new(loot_sub_category_label(item)).small().color(credential_category_color(item)),
    );
    ui.monospace(&item.agent_id);
    ui.label(&item.source);
    ui.label(blank_if_empty(&item.collected_at, "-"));
    if let Some(preview) = &item.preview {
        let display = ellipsize(preview, 80);
        ui.label(RichText::new(display).monospace().color(Color32::from_rgb(110, 199, 141)));
    } else {
        ui.label("-");
    }
    ui.end_row();
}

pub(crate) fn render_loot_file_row(
    ui: &mut egui::Ui,
    item: &LootItem,
    status_message: &mut Option<String>,
) {
    ui.label(&item.name);
    ui.label(RichText::new(loot_sub_category_label(item)).small().color(Color32::GRAY));
    ui.monospace(&item.agent_id);
    ui.label(item.file_path.as_deref().unwrap_or("-"));
    ui.label(item.size_bytes.map(human_size).unwrap_or_else(|| "-".to_owned()));
    ui.label(blank_if_empty(&item.collected_at, "-"));
    if loot_is_downloadable(item) {
        if ui.button("Save").clicked() {
            *status_message = Some(download_loot_item(item).unwrap_or_else(|e| e));
        }
    } else {
        ui.label("");
    }
    ui.end_row();
}

pub(crate) fn loot_matches_filters(
    item: &LootItem,
    type_filter: LootTypeFilter,
    cred_filter: CredentialSubFilter,
    file_filter: FileSubFilter,
    agent_filter: &str,
    since_filter: &str,
    until_filter: &str,
    text_filter: &str,
) -> bool {
    if !matches_loot_type_filter(item, type_filter, cred_filter, file_filter) {
        return false;
    }

    if !contains_ascii_case_insensitive(&item.agent_id, agent_filter) {
        return false;
    }

    // Time range filtering: `since_filter` is an inclusive lower bound, `until_filter` is an
    // inclusive upper bound.  Both are matched as string prefixes against `collected_at` so that
    // partial date strings like "2026-03" work as expected.
    let since = since_filter.trim();
    if !since.is_empty() && item.collected_at.as_str() < since {
        return false;
    }
    let until = until_filter.trim();
    if !until.is_empty() && item.collected_at.as_str() > until {
        return false;
    }

    [
        item.name.as_str(),
        item.source.as_str(),
        item.agent_id.as_str(),
        item.file_path.as_deref().unwrap_or_default(),
        item.preview.as_deref().unwrap_or_default(),
    ]
    .into_iter()
    .any(|field| contains_ascii_case_insensitive(field, text_filter))
}

pub(crate) fn matches_loot_type_filter(
    item: &LootItem,
    type_filter: LootTypeFilter,
    cred_filter: CredentialSubFilter,
    file_filter: FileSubFilter,
) -> bool {
    match type_filter {
        LootTypeFilter::All => true,
        LootTypeFilter::Credentials => {
            if !matches!(item.kind, LootKind::Credential) {
                return false;
            }
            matches_credential_sub_filter(item, cred_filter)
        }
        LootTypeFilter::Files => {
            if !matches!(item.kind, LootKind::File) {
                return false;
            }
            matches_file_sub_filter(item, file_filter)
        }
        LootTypeFilter::Screenshots => matches!(item.kind, LootKind::Screenshot),
    }
}

/// Detect a credential sub-category from name/preview/source heuristics.
pub(crate) fn detect_credential_category(item: &LootItem) -> CredentialSubFilter {
    let haystack =
        [item.name.as_str(), item.source.as_str(), item.preview.as_deref().unwrap_or_default()]
            .join(" ")
            .to_ascii_lowercase();

    if haystack.contains("ntlm") || haystack.contains("lm hash") || haystack.contains("nthash") {
        CredentialSubFilter::NtlmHash
    } else if haystack.contains("kerberos")
        || haystack.contains("kirbi")
        || haystack.contains(".ccache")
        || haystack.contains("tgt")
        || haystack.contains("tgs")
    {
        CredentialSubFilter::KerberosTicket
    } else if haystack.contains("certificate")
        || haystack.contains(".pfx")
        || haystack.contains(".pem")
        || haystack.contains(".crt")
        || haystack.contains(".cer")
    {
        CredentialSubFilter::Certificate
    } else if haystack.contains("plaintext")
        || haystack.contains("password")
        || haystack.contains("passwd")
        || haystack.contains("cleartext")
    {
        CredentialSubFilter::Plaintext
    } else {
        CredentialSubFilter::All
    }
}

/// Detect a file sub-category from the file extension or name.
pub(crate) fn detect_file_category(item: &LootItem) -> FileSubFilter {
    let path_str = item.file_path.as_deref().unwrap_or(item.name.as_str()).to_ascii_lowercase();
    let ext =
        std::path::Path::new(&path_str).extension().and_then(|e| e.to_str()).unwrap_or_default();

    const DOCUMENT_EXTS: &[&str] = &[
        "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "odt", "ods", "csv",
        "md", "html", "htm", "xml", "json", "yaml", "yml",
    ];
    const ARCHIVE_EXTS: &[&str] =
        &["zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab", "iso", "tgz"];

    if DOCUMENT_EXTS.contains(&ext) {
        FileSubFilter::Document
    } else if ARCHIVE_EXTS.contains(&ext) {
        FileSubFilter::Archive
    } else if !ext.is_empty() {
        // Anything with an extension that is not a known document/archive is treated as binary.
        FileSubFilter::Binary
    } else {
        // No extension — heuristic: if the name contains "bin" or the path is a known binary
        // location, call it binary; otherwise treat as unknown (pass through).
        if path_str.contains("/bin/")
            || path_str.contains("\\bin\\")
            || ext == "exe"
            || ext == "dll"
        {
            FileSubFilter::Binary
        } else {
            FileSubFilter::All
        }
    }
}

pub(crate) fn matches_credential_sub_filter(item: &LootItem, filter: CredentialSubFilter) -> bool {
    if filter == CredentialSubFilter::All {
        return true;
    }
    detect_credential_category(item) == filter
}

pub(crate) fn matches_file_sub_filter(item: &LootItem, filter: FileSubFilter) -> bool {
    if filter == FileSubFilter::All {
        return true;
    }
    detect_file_category(item) == filter
}

/// Returns a short human-readable sub-category label for display in the loot list.
pub(crate) fn loot_sub_category_label(item: &LootItem) -> &'static str {
    match item.kind {
        LootKind::Credential => match detect_credential_category(item) {
            CredentialSubFilter::NtlmHash => "NTLM Hash",
            CredentialSubFilter::Plaintext => "Plaintext",
            CredentialSubFilter::KerberosTicket => "Kerberos",
            CredentialSubFilter::Certificate => "Certificate",
            CredentialSubFilter::All => "",
        },
        LootKind::File => match detect_file_category(item) {
            FileSubFilter::Document => "Document",
            FileSubFilter::Archive => "Archive",
            FileSubFilter::Binary => "Binary",
            FileSubFilter::All => "",
        },
        _ => "",
    }
}

/// Returns a color hint for the credential sub-category (for the table "Type" column).
pub(crate) fn credential_category_color(item: &LootItem) -> Color32 {
    match detect_credential_category(item) {
        CredentialSubFilter::NtlmHash => Color32::from_rgb(220, 160, 60), // amber
        CredentialSubFilter::Plaintext => Color32::from_rgb(110, 199, 141), // green
        CredentialSubFilter::KerberosTicket => Color32::from_rgb(140, 120, 220), // purple
        CredentialSubFilter::Certificate => Color32::from_rgb(80, 180, 220), // cyan
        CredentialSubFilter::All => Color32::GRAY,
    }
}

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

pub(crate) fn csv_field(value: &str) -> String {
    // Neutralize spreadsheet formula injection: prepend a single-quote to any value whose
    // first non-whitespace character is a formula trigger (`=`, `+`, `-`, `@`).  Loot data
    // is adversary-controlled, so an attacker on the target host could craft a credential
    // name or file path like `=EXEC("malware.exe")` that executes when an operator opens the
    // exported CSV in Excel or LibreOffice Calc.
    let effective: String = if value.trim_start().starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if effective.contains(',')
        || effective.contains('"')
        || effective.contains('\n')
        || effective.contains('\r')
    {
        format!("\"{}\"", effective.replace('"', "\"\""))
    } else {
        effective
    }
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

pub(crate) fn json_str(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!("\"{escaped}\"")
}

pub(crate) fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let trimmed = needle.trim();
    trimmed.is_empty() || haystack.to_ascii_lowercase().contains(&trimmed.to_ascii_lowercase())
}

pub(crate) fn loot_is_downloadable(item: &LootItem) -> bool {
    matches!(item.kind, LootKind::File | LootKind::Screenshot) && item.content_base64.is_some()
}

/// Opens a native save-file dialog for a completed file-browser download.
///
/// The suggested file name is derived from `remote_path`.  If the user accepts, the
/// bytes are written to the chosen path.  Status messages are shown via the OS dialog.
pub(crate) fn save_completed_download(remote_path: &str, data: &[u8]) {
    let file_name = std::path::Path::new(remote_path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(sanitize_file_name)
        .unwrap_or_else(|| "download.bin".to_owned());

    let Some(destination) = FileDialog::new().set_file_name(&file_name).save_file() else {
        return;
    };

    // Ignore the error — the OS dialog already shows write errors to the user.
    let _ = std::fs::write(destination, data);
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

// ── File-browser helpers ──────────────────────────────────────────────────────

pub(crate) fn blank_if_empty<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.trim().is_empty() { fallback } else { value }
}

pub(crate) fn upload_destination(
    browser: Option<&AgentFileBrowserState>,
    selected_path: Option<&str>,
) -> Option<String> {
    selected_remote_directory(browser, selected_path)
        .or_else(|| browser.and_then(|state| state.current_dir.clone()))
}

pub(crate) fn selected_remote_directory(
    browser: Option<&AgentFileBrowserState>,
    selected_path: Option<&str>,
) -> Option<String> {
    selected_path.and_then(|path| {
        browser.and_then(|state| {
            find_file_entry(state, path).map(|entry| {
                if entry.is_dir {
                    entry.path.clone()
                } else {
                    parent_remote_path(&entry.path).unwrap_or_else(|| entry.path.clone())
                }
            })
        })
    })
}

pub(crate) fn find_file_entry<'a>(
    browser: &'a AgentFileBrowserState,
    path: &str,
) -> Option<&'a FileBrowserEntry> {
    browser.directories.values().flat_map(|entries| entries.iter()).find(|entry| entry.path == path)
}

pub(crate) fn parent_remote_path(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches(['\\', '/']);
    if trimmed.is_empty() {
        return None;
    }

    if let Some(index) = trimmed.rfind(['\\', '/']) {
        let parent = &trimmed[..=index];
        if parent.is_empty() { None } else { Some(parent.to_owned()) }
    } else {
        None
    }
}

pub(crate) fn join_remote_path(base: &str, name: &str) -> String {
    if base.is_empty() {
        return name.to_owned();
    }

    let separator = if base.contains('\\') { '\\' } else { '/' };
    if base.ends_with('\\') || base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}{separator}{name}")
    }
}

/// Split a remote path into `(label, cumulative_path)` pairs for breadcrumb rendering.
pub(crate) fn breadcrumb_segments(path: &str) -> Vec<(String, String)> {
    let sep = if path.contains('\\') { '\\' } else { '/' };
    let mut segments = Vec::new();

    // Handle Windows drive root: "C:\\" → segment ("C:\\", "C:\\")
    let trimmed_for_check = path.trim_end_matches(sep);
    if trimmed_for_check.len() >= 2 && trimmed_for_check.as_bytes()[1] == b':' {
        let drive_root = format!("{}:{sep}", &trimmed_for_check[..1]);
        segments.push((drive_root.clone(), drive_root.clone()));

        let rest_start = drive_root.len().min(path.len());
        let rest = path[rest_start..].trim_matches(sep);
        if !rest.is_empty() {
            let mut cumulative = drive_root;
            for part in rest.split(sep) {
                if part.is_empty() {
                    continue;
                }
                cumulative = format!("{cumulative}{part}{sep}");
                segments.push((part.to_owned(), cumulative.clone()));
            }
        }
        return segments;
    }

    // Unix-style: starts with "/"
    if path.starts_with(sep) {
        let root = sep.to_string();
        segments.push((root.clone(), root.clone()));

        let rest = path[1..].trim_end_matches(sep);
        if !rest.is_empty() {
            let mut cumulative = String::from(sep);
            for part in rest.split(sep) {
                if part.is_empty() {
                    continue;
                }
                cumulative = format!("{cumulative}{part}{sep}");
                segments.push((part.to_owned(), cumulative.clone()));
            }
        }
        return segments;
    }

    // Relative path — just split on separator
    let mut cumulative = String::new();
    for part in path.trim_end_matches(sep).split(sep) {
        if part.is_empty() {
            continue;
        }
        if cumulative.is_empty() {
            cumulative = format!("{part}{sep}");
        } else {
            cumulative = format!("{cumulative}{part}{sep}");
        }
        segments.push((part.to_owned(), cumulative.clone()));
    }
    segments
}

pub(crate) fn directory_label(path: &str) -> String {
    if path.ends_with(':') || path.ends_with(":\\") || path.ends_with(":/") {
        return path.to_owned();
    }

    let trimmed = path.trim_end_matches(['\\', '/']);
    Path::new(trimmed)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or(trimmed)
        .to_owned()
}

pub(crate) fn file_entry_label(entry: &FileBrowserEntry) -> String {
    let size = if entry.size_label.trim().is_empty() { "-" } else { entry.size_label.as_str() };
    let modified = blank_if_empty(&entry.modified_at, "-");
    let permissions = blank_if_empty(&entry.permissions, "-");
    format!("{}  [{size} | {modified} | {permissions}]", entry.name)
}

pub(crate) fn human_size(size_bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];

    let mut size = size_bytes as f64;
    let mut unit = 0_usize;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{size_bytes} {}", UNITS[unit])
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}
