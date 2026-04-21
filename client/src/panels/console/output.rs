use eframe::egui::{Color32, RichText};

use crate::transport::{AgentConsoleEntry, AgentConsoleEntryKind};
use crate::{ClientApp, blank_if_empty, short_task_id};

impl ClientApp {
    pub(crate) fn render_console_output_panel(
        &self,
        ui: &mut eframe::egui::Ui,
        agent_id: &str,
        entries: &[AgentConsoleEntry],
    ) {
        ui.heading("Console Output");
        ui.separator();
        eframe::egui::ScrollArea::vertical()
            .id_salt(("console-output", agent_id))
            .stick_to_bottom(true)
            .max_height(360.0)
            .show(ui, |ui| {
                if entries.is_empty() {
                    ui.label("No console output for this session yet.");
                } else {
                    for entry in entries {
                        self.render_console_entry(ui, entry);
                        ui.add_space(4.0);
                    }
                }
            });
    }

    pub(crate) fn render_console_entry(
        &self,
        ui: &mut eframe::egui::Ui,
        entry: &AgentConsoleEntry,
    ) {
        let accent = match entry.kind {
            AgentConsoleEntryKind::Output => Color32::from_rgb(110, 199, 141),
            AgentConsoleEntryKind::Error => Color32::from_rgb(215, 83, 83),
        };

        let task_color = task_id_color(&entry.task_id);

        ui.group(|ui| {
            ui.horizontal_wrapped(|ui| {
                let timestamp = blank_if_empty(&entry.received_at, "pending");
                ui.label(RichText::new(timestamp).weak().monospace());
                ui.separator();
                ui.colored_label(accent, RichText::new(&entry.command_id).monospace());
                if !entry.task_id.is_empty() {
                    ui.separator();
                    let tag = format!("[t:{}]", short_task_id(&entry.task_id));
                    ui.colored_label(task_color, RichText::new(tag).monospace().strong());
                }
                if let Some(command_line) = &entry.command_line {
                    if !command_line.trim().is_empty() {
                        ui.separator();
                        ui.label(RichText::new(command_line).monospace().weak());
                    }
                }
            });
            ui.add_space(2.0);
            ui.label(RichText::new(&entry.output).monospace().color(accent));
        });
    }
}

/// Deterministically maps a task ID to a display color from a fixed palette.
///
/// The same task ID always produces the same color within a session, making it
/// easy to visually correlate interleaved output chunks.
pub(crate) fn task_id_color(task_id: &str) -> Color32 {
    const PALETTE: &[Color32] = &[
        Color32::from_rgb(100, 180, 255), // sky blue
        Color32::from_rgb(255, 180, 80),  // amber
        Color32::from_rgb(200, 130, 255), // lavender
        Color32::from_rgb(80, 220, 200),  // teal
        Color32::from_rgb(255, 120, 150), // rose
        Color32::from_rgb(160, 230, 80),  // lime
        Color32::from_rgb(255, 220, 60),  // yellow
        Color32::from_rgb(120, 200, 180), // sage
    ];

    if task_id.is_empty() {
        return Color32::from_rgb(160, 160, 160);
    }

    // Hash the task ID to a palette index using a simple FNV-1a fold.
    let hash = task_id
        .bytes()
        .fold(2_166_136_261_u32, |acc, b| acc.wrapping_mul(16_777_619) ^ u32::from(b));
    PALETTE[(hash as usize) % PALETTE.len()]
}
