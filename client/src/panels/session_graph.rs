use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, Sense, Stroke};

use crate::transport::AppState;
use crate::{
    ClientApp, SESSION_GRAPH_HEIGHT, SESSION_GRAPH_MAX_ZOOM, SESSION_GRAPH_MIN_ZOOM,
    SESSION_GRAPH_ROOT_ID, SessionAction, SessionGraphNodeKind, SessionGraphState,
    build_session_graph, graph_node_position, graph_node_size, session_graph_node_rect,
    session_graph_status_color, session_graph_world_to_screen,
};

impl ClientApp {
    pub(crate) fn render_session_graph_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
        ui.horizontal_wrapped(|ui| {
            ui.heading("Session Graph");
            ui.separator();
            ui.label("Drag to pan, scroll to zoom.");
            if ui.button("Reset View").clicked() {
                self.session_panel.graph_state = SessionGraphState::default();
            }
        });
        ui.add_space(6.0);

        let layout = build_session_graph(&state.agents);
        let desired_size = egui::vec2(ui.available_width(), SESSION_GRAPH_HEIGHT);
        let (rect, response) = ui.allocate_exact_size(desired_size, Sense::click_and_drag());
        let painter = ui.painter_at(rect);

        painter.rect_filled(rect, 10.0, Color32::from_rgb(18, 20, 24));
        painter.rect_stroke(
            rect,
            10.0,
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(255, 255, 255, 24)),
            egui::StrokeKind::Middle,
        );

        if response.dragged() {
            self.session_panel.graph_state.pan += ui.input(|input| input.pointer.delta());
            ui.ctx().request_repaint();
        }

        if response.hovered() {
            let scroll_delta = ui.input(|input| input.raw_scroll_delta.y);
            if scroll_delta.abs() > f32::EPSILON {
                let old_zoom = self.session_panel.graph_state.zoom;
                let zoom_factor = (1.0 + scroll_delta * 0.0015).clamp(0.8, 1.25);
                let new_zoom =
                    (old_zoom * zoom_factor).clamp(SESSION_GRAPH_MIN_ZOOM, SESSION_GRAPH_MAX_ZOOM);
                if (new_zoom - old_zoom).abs() > f32::EPSILON {
                    if let Some(pointer_pos) = response.hover_pos() {
                        let local = pointer_pos - rect.center();
                        self.session_panel.graph_state.pan = local
                            - (local - self.session_panel.graph_state.pan) * (new_zoom / old_zoom);
                    }
                    self.session_panel.graph_state.zoom = new_zoom;
                    ui.ctx().request_repaint();
                }
            }
        }

        let hovered_node = response.hover_pos().and_then(|pointer| {
            layout
                .nodes
                .iter()
                .find(|node| {
                    session_graph_node_rect(
                        rect,
                        &self.session_panel.graph_state,
                        node.position,
                        node.size,
                    )
                    .contains(pointer)
                })
                .map(|node| node.id.clone())
        });

        if hovered_node.is_some() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }

        if response.clicked()
            && let (Some(pointer), Some(node_id)) =
                (response.interact_pointer_pos(), hovered_node.clone())
            && node_id != SESSION_GRAPH_ROOT_ID
            && session_graph_node_rect(
                rect,
                &self.session_panel.graph_state,
                graph_node_position(&layout, &node_id).unwrap_or(Pos2::ZERO),
                graph_node_size(&layout, &node_id).unwrap_or(egui::Vec2::ZERO),
            )
            .contains(pointer)
        {
            self.handle_session_action(
                SessionAction::OpenConsole(node_id),
                state.operator_info.as_ref().map(|operator| operator.username.as_str()),
            );
        }

        for edge in &layout.edges {
            let Some(from) = graph_node_position(&layout, &edge.from) else {
                continue;
            };
            let Some(to) = graph_node_position(&layout, &edge.to) else {
                continue;
            };
            let from_size = graph_node_size(&layout, &edge.from).unwrap_or(egui::Vec2::ZERO);
            let to_size = graph_node_size(&layout, &edge.to).unwrap_or(egui::Vec2::ZERO);
            let start = session_graph_world_to_screen(
                rect,
                &self.session_panel.graph_state,
                Pos2::new(from.x, from.y + from_size.y * 0.5),
            );
            let end = session_graph_world_to_screen(
                rect,
                &self.session_panel.graph_state,
                Pos2::new(to.x, to.y - to_size.y * 0.5),
            );
            let mid_y = (start.y + end.y) * 0.5;
            painter.line_segment(
                [start, Pos2::new(start.x, mid_y)],
                Stroke::new(2.0, Color32::from_rgb(92, 112, 140)),
            );
            painter.line_segment(
                [Pos2::new(start.x, mid_y), Pos2::new(end.x, mid_y)],
                Stroke::new(2.0, Color32::from_rgb(92, 112, 140)),
            );
            painter.line_segment(
                [Pos2::new(end.x, mid_y), end],
                Stroke::new(2.0, Color32::from_rgb(92, 112, 140)),
            );
        }

        for node in &layout.nodes {
            let node_rect = session_graph_node_rect(
                rect,
                &self.session_panel.graph_state,
                node.position,
                node.size,
            );
            let fill = match node.kind {
                SessionGraphNodeKind::Teamserver => Color32::from_rgb(36, 84, 122),
                SessionGraphNodeKind::Agent => session_graph_status_color(&node.status),
            };
            let stroke_color = if hovered_node.as_deref() == Some(node.id.as_str()) {
                Color32::WHITE
            } else {
                Color32::from_rgba_unmultiplied(255, 255, 255, 56)
            };
            painter.rect_filled(node_rect, 8.0, fill);
            painter.rect_stroke(
                node_rect,
                8.0,
                Stroke::new(1.5, stroke_color),
                egui::StrokeKind::Middle,
            );
            painter.text(
                Pos2::new(node_rect.center().x, node_rect.center().y - 10.0),
                Align2::CENTER_CENTER,
                &node.title,
                FontId::proportional(16.0),
                Color32::WHITE,
            );
            painter.text(
                Pos2::new(node_rect.center().x, node_rect.center().y + 10.0),
                Align2::CENTER_CENTER,
                &node.subtitle,
                FontId::monospace(13.0),
                Color32::from_rgb(228, 232, 237),
            );
        }

        let legend_rect =
            Rect::from_min_size(rect.left_top() + egui::vec2(12.0, 12.0), egui::vec2(210.0, 48.0));
        painter.rect_filled(legend_rect, 8.0, Color32::from_rgba_unmultiplied(8, 10, 14, 190));
        painter.circle_filled(
            legend_rect.left_center() + egui::vec2(18.0, -10.0),
            5.0,
            Color32::from_rgb(84, 170, 110),
        );
        painter.text(
            legend_rect.left_center() + egui::vec2(30.0, -10.0),
            Align2::LEFT_CENTER,
            "Alive",
            FontId::proportional(13.0),
            Color32::WHITE,
        );
        painter.circle_filled(
            legend_rect.left_center() + egui::vec2(88.0, -10.0),
            5.0,
            Color32::from_rgb(174, 68, 68),
        );
        painter.text(
            legend_rect.left_center() + egui::vec2(100.0, -10.0),
            Align2::LEFT_CENTER,
            "Dead",
            FontId::proportional(13.0),
            Color32::WHITE,
        );
        painter.circle_filled(
            legend_rect.left_center() + egui::vec2(150.0, -10.0),
            5.0,
            Color32::from_rgb(36, 84, 122),
        );
        painter.text(
            legend_rect.left_center() + egui::vec2(162.0, -10.0),
            Align2::LEFT_CENTER,
            "Root",
            FontId::proportional(13.0),
            Color32::WHITE,
        );

        if layout.nodes.len() == 1 {
            painter.text(
                rect.center_bottom() + egui::vec2(0.0, -18.0),
                Align2::CENTER_CENTER,
                "No agent topology available yet.",
                FontId::proportional(15.0),
                Color32::from_gray(170),
            );
        }
    }
}
