//! Havoc-style dark theme for egui.

use eframe::egui::{self, Color32, Shadow, Stroke};

/// Build an egui `Visuals` matching Havoc C2's dark navy theme.
pub(crate) fn havoc_dark_theme() -> egui::Visuals {
    let mut visuals = egui::Visuals::dark();

    // Havoc background: dark navy (~#1a1a2e / #16162a)
    let bg_dark = Color32::from_rgb(22, 22, 42);
    let bg_panel = Color32::from_rgb(26, 26, 46);
    let bg_widget = Color32::from_rgb(36, 36, 60);
    let bg_widget_hover = Color32::from_rgb(46, 46, 76);
    let bg_widget_active = Color32::from_rgb(56, 56, 90);
    let accent = Color32::from_rgb(140, 80, 200); // purple accent
    let text_primary = Color32::from_rgb(220, 220, 230);
    let text_secondary = Color32::from_rgb(160, 160, 180);

    visuals.panel_fill = bg_panel;
    visuals.window_fill = bg_dark;
    visuals.extreme_bg_color = bg_dark;
    visuals.faint_bg_color = Color32::from_rgb(30, 30, 50);

    // Widget styles
    visuals.widgets.noninteractive.bg_fill = bg_panel;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, text_secondary);
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(50, 50, 70));

    visuals.widgets.inactive.bg_fill = bg_widget;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, text_primary);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(60, 60, 80));

    visuals.widgets.hovered.bg_fill = bg_widget_hover;
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.5, Color32::WHITE);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, accent);

    visuals.widgets.active.bg_fill = bg_widget_active;
    visuals.widgets.active.fg_stroke = Stroke::new(2.0, Color32::WHITE);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, accent);

    visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(140, 80, 200, 80);
    visuals.selection.stroke = Stroke::new(1.0, accent);

    // Window shadow + separator
    visuals.window_shadow =
        Shadow { offset: [0, 2], blur: 8, spread: 0, color: Color32::from_black_alpha(120) };
    visuals.popup_shadow = visuals.window_shadow;

    visuals.override_text_color = Some(text_primary);

    visuals
}
