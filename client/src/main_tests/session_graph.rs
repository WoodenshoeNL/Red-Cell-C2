use super::*;

#[test]
fn build_session_graph_uses_explicit_pivot_parent() {
    let mut child = sample_agent("BBBB0002", "wkstn-2", "bob", false, "10/03/2026 12:01:00");
    child.pivot_parent = Some("AAAA0001".to_owned());
    let agents =
        vec![sample_agent("AAAA0001", "wkstn-1", "alice", false, "10/03/2026 12:00:00"), child];

    let graph = build_session_graph(&agents);

    assert!(graph.edges.iter().any(|edge| edge.from == "AAAA0001" && edge.to == "BBBB0002"));
    assert!(
        graph.edges.iter().any(|edge| edge.from == SESSION_GRAPH_ROOT_ID && edge.to == "AAAA0001")
    );
}

#[test]
fn build_session_graph_falls_back_to_pivot_links() {
    let mut parent = sample_agent("AAAA0001", "wkstn-1", "alice", false, "10/03/2026 12:00:00");
    parent.pivot_links.push("BBBB0002".to_owned());
    let child = sample_agent("BBBB0002", "wkstn-2", "bob", false, "10/03/2026 12:01:00");

    let graph = build_session_graph(&[parent, child]);

    assert!(graph.edges.iter().any(|edge| edge.from == "AAAA0001" && edge.to == "BBBB0002"));
}

#[test]
fn agent_is_active_status_matches_expected_markers() {
    assert!(agent_is_active_status("Alive"));
    assert!(agent_is_active_status("true"));
    assert!(!agent_is_active_status("Dead"));
    assert!(!agent_is_active_status("Offline"));
}
