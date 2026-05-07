use super::*;

fn make_loot(kind: LootKind) -> LootItem {
    LootItem {
        id: Some(1),
        kind,
        name: "test".to_owned(),
        agent_id: "agent-1".to_owned(),
        source: "source".to_owned(),
        collected_at: "2026-03-18T12:00:00Z".to_owned(),
        file_path: None,
        size_bytes: None,
        content_base64: None,
        preview: None,
    }
}

mod categories;
mod download;
mod export;
mod file_names;
mod filters;
