mod dispatch;
mod serialize;
mod types;

// Re-exported for test modules in transport::tests which import via operator_msg::{…}.
#[allow(unused_imports)]
pub(super) use serialize::{
    flat_info_string, loot_item_from_flat_info, loot_item_from_response, normalize_agent_id,
    sanitize_text,
};
