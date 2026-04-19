//! egui layout helpers, widget builders, and color utilities.

use eframe::egui::{self, Color32, RichText};

use super::clipboard::download_loot_item;
use super::format::{
    blank_if_empty, detect_credential_category, ellipsize, human_size, loot_is_downloadable,
    loot_sub_category_label,
};
use crate::python::{ScriptLoadStatus, ScriptOutputStream};
use crate::transport::{ConnectedOperatorState, LootItem};
use crate::{CredentialSortColumn, LootPanelState};

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

pub(crate) fn script_status_color(status: ScriptLoadStatus) -> Color32 {
    match status {
        ScriptLoadStatus::Loaded => Color32::from_rgb(110, 199, 141),
        ScriptLoadStatus::Error => Color32::from_rgb(215, 83, 83),
        ScriptLoadStatus::Unloaded => Color32::from_rgb(232, 182, 83),
    }
}

pub(crate) fn script_output_color(stream: ScriptOutputStream) -> Color32 {
    match stream {
        ScriptOutputStream::Stdout => Color32::from_rgb(110, 199, 141),
        ScriptOutputStream::Stderr => Color32::from_rgb(215, 83, 83),
    }
}

// ── Loot UI helpers ───────────────────────────────────────────────────────────

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

/// Returns a color hint for the credential sub-category (for the table "Type" column).
pub(crate) fn credential_category_color(item: &LootItem) -> Color32 {
    match detect_credential_category(item) {
        crate::CredentialSubFilter::NtlmHash => Color32::from_rgb(220, 160, 60), // amber
        crate::CredentialSubFilter::Plaintext => Color32::from_rgb(110, 199, 141), // green
        crate::CredentialSubFilter::KerberosTicket => Color32::from_rgb(140, 120, 220), // purple
        crate::CredentialSubFilter::Certificate => Color32::from_rgb(80, 180, 220), // cyan
        crate::CredentialSubFilter::All => Color32::GRAY,
    }
}
