use std::collections::{BTreeMap, BTreeSet};

use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, Sense, Stroke};

use crate::transport::{self, AppState};
use crate::{
    ClientApp, SESSION_GRAPH_HEIGHT, SESSION_GRAPH_MAX_ZOOM, SESSION_GRAPH_MIN_ZOOM,
    SESSION_GRAPH_ROOT_ID, SessionAction, SessionGraphEdge, SessionGraphLayout, SessionGraphNode,
    SessionGraphNodeKind, SessionGraphState,
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

// ─── Session graph layout helpers ────────────────────────────────────────────

pub(crate) fn build_session_graph(agents: &[transport::AgentSummary]) -> SessionGraphLayout {
    let mut sorted_agents = agents.to_vec();
    sorted_agents.sort_by(|left, right| left.name_id.cmp(&right.name_id));

    let known_ids =
        sorted_agents.iter().map(|agent| agent.name_id.clone()).collect::<BTreeSet<_>>();
    let mut parent_by_child = BTreeMap::new();

    for agent in &sorted_agents {
        if let Some(parent) = agent
            .pivot_parent
            .as_deref()
            .filter(|parent| known_ids.contains(*parent))
            .filter(|parent| *parent != agent.name_id)
        {
            parent_by_child.insert(agent.name_id.clone(), parent.to_owned());
        }
    }

    for agent in &sorted_agents {
        for child in &agent.pivot_links {
            if child != &agent.name_id
                && known_ids.contains(child)
                && !parent_by_child.contains_key(child)
            {
                parent_by_child.insert(child.clone(), agent.name_id.clone());
            }
        }
    }

    let mut children = BTreeMap::<String, Vec<String>>::new();
    children.entry(SESSION_GRAPH_ROOT_ID.to_owned()).or_default();
    for agent in &sorted_agents {
        let parent = parent_by_child
            .get(&agent.name_id)
            .cloned()
            .unwrap_or_else(|| SESSION_GRAPH_ROOT_ID.to_owned());
        children.entry(parent).or_default().push(agent.name_id.clone());
    }
    for child_ids in children.values_mut() {
        child_ids.sort();
    }

    let mut positions = BTreeMap::new();
    let mut next_leaf = 0.0;
    assign_session_graph_positions(
        SESSION_GRAPH_ROOT_ID,
        0,
        &children,
        &mut next_leaf,
        &mut positions,
    );

    let mut nodes = vec![SessionGraphNode {
        id: SESSION_GRAPH_ROOT_ID.to_owned(),
        title: "Teamserver".to_owned(),
        subtitle: "root".to_owned(),
        status: "Online".to_owned(),
        position: positions.get(SESSION_GRAPH_ROOT_ID).copied().unwrap_or(Pos2::ZERO),
        size: egui::vec2(148.0, 52.0),
        kind: SessionGraphNodeKind::Teamserver,
    }];

    for agent in sorted_agents {
        nodes.push(SessionGraphNode {
            title: if agent.hostname.trim().is_empty() {
                agent.name_id.clone()
            } else {
                agent.hostname.clone()
            },
            subtitle: agent.name_id.clone(),
            status: agent.status.clone(),
            position: positions.get(&agent.name_id).copied().unwrap_or(Pos2::ZERO),
            size: egui::vec2(138.0, 58.0),
            id: agent.name_id,
            kind: SessionGraphNodeKind::Agent,
        });
    }

    let mut edges = Vec::new();
    for (parent, child_ids) in children {
        for child in child_ids {
            edges.push(SessionGraphEdge { from: parent.clone(), to: child });
        }
    }

    SessionGraphLayout { nodes, edges }
}

fn assign_session_graph_positions(
    node_id: &str,
    depth: usize,
    children: &BTreeMap<String, Vec<String>>,
    next_leaf: &mut f32,
    positions: &mut BTreeMap<String, Pos2>,
) -> f32 {
    const H_SPACING: f32 = 220.0;
    const V_SPACING: f32 = 120.0;

    let child_ids = children.get(node_id).cloned().unwrap_or_default();
    let x = if child_ids.is_empty() {
        let x = *next_leaf * H_SPACING;
        *next_leaf += 1.0;
        x
    } else {
        let child_xs = child_ids
            .iter()
            .map(|child| {
                assign_session_graph_positions(child, depth + 1, children, next_leaf, positions)
            })
            .collect::<Vec<_>>();
        let first = child_xs.first().copied().unwrap_or(*next_leaf * H_SPACING);
        let last = child_xs.last().copied().unwrap_or(first);
        (first + last) * 0.5
    };

    positions.insert(node_id.to_owned(), Pos2::new(x, depth as f32 * V_SPACING));
    x
}

pub(crate) fn graph_node_position(layout: &SessionGraphLayout, node_id: &str) -> Option<Pos2> {
    layout.nodes.iter().find(|node| node.id == node_id).map(|node| node.position)
}

pub(crate) fn graph_node_size(layout: &SessionGraphLayout, node_id: &str) -> Option<egui::Vec2> {
    layout.nodes.iter().find(|node| node.id == node_id).map(|node| node.size)
}

pub(crate) fn session_graph_world_to_screen(
    rect: Rect,
    graph_state: &SessionGraphState,
    world: Pos2,
) -> Pos2 {
    rect.center() + graph_state.pan + world.to_vec2() * graph_state.zoom
}

pub(crate) fn session_graph_node_rect(
    rect: Rect,
    graph_state: &SessionGraphState,
    world_center: Pos2,
    world_size: egui::Vec2,
) -> Rect {
    let center = session_graph_world_to_screen(rect, graph_state, world_center);
    Rect::from_center_size(center, world_size * graph_state.zoom)
}

pub(crate) fn session_graph_status_color(status: &str) -> Color32 {
    if agent_is_active_status(status) {
        Color32::from_rgb(84, 170, 110)
    } else {
        Color32::from_rgb(174, 68, 68)
    }
}

pub(crate) fn agent_is_active_status(status: &str) -> bool {
    matches!(status.trim().to_ascii_lowercase().as_str(), "alive" | "active" | "online" | "true")
}
