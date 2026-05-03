//! Correlate Demon / REST task identifiers across API surfaces.
//!
//! Task IDs may appear as unpadded lowercase hex in JSON metadata (`request_id`),
//! padded 8-character uppercase IDs from the teamserver `next_task_id` helper, or the
//! top-level loot summary field depending on ingest path — [`hex_correlation_tokens_equal`]
//! treats those representations as identical.

use serde_json::Value;

#[inline]
fn parse_hex_u32_trimmed(token: &str) -> Option<u32> {
    let t = token.trim();
    let digits = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if digits.is_empty() {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

/// Returns true when `value` parses as hexadecimal and is plausibly a u32 Demon request id /
/// REST task label (not an opaque decimal row surrogate such as SQLite `agent_responses.id`).
#[must_use]
pub(crate) fn is_plausible_hex_task_token(value: &str) -> bool {
    let t = value.trim();
    let digits = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if digits.is_empty() || digits.len() > 8 {
        return false;
    }
    if !digits.chars().all(|c| c.is_ascii_hexdigit()) || parse_hex_u32_trimmed(digits).is_none() {
        return false;
    }
    // Canonical width from `Teamserver next_task_id` / Demon correlation.
    if digits.len() == 8 {
        return true;
    }
    // Shorter blobs must include A–F so we don't treat decimal-looking strings (`"172"` …) as hex.
    digits.chars().any(|ch| matches!(ch, 'a'..='f' | 'A'..='F'))
}

#[must_use]
pub(crate) fn hex_correlation_tokens_equal(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    if !is_plausible_hex_task_token(a) || !is_plausible_hex_task_token(b) {
        return false;
    }
    match (parse_hex_u32_trimmed(a), parse_hex_u32_trimmed(b)) {
        (Some(na), Some(nb)) => na == nb,
        _ => false,
    }
}

/// Matches a loot summary row (`task_id` and optional `metadata`) against the queued task id for
/// an `agent download` poll.
#[must_use]
pub(crate) fn loot_matches_expected_task_id(
    expected: &str,
    summary_task_id: Option<&str>,
    metadata: Option<&Value>,
) -> bool {
    if summary_task_id.is_some_and(|token| hex_correlation_tokens_equal(expected, token)) {
        return true;
    }
    let Some(Value::Object(obj)) = metadata else {
        return false;
    };
    for key in ["task_id", "request_id"] {
        let Some(Value::String(s)) = obj.get(key) else {
            continue;
        };
        if hex_correlation_tokens_equal(expected, s) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn plausible_token_accepts_fixed_width_even_if_digits_only() {
        assert!(is_plausible_hex_task_token("12345678"));
        assert!(is_plausible_hex_task_token("0000002a"));
        assert!(is_plausible_hex_task_token("DEADBEEF"));
    }

    #[test]
    fn plausible_token_rejects_short_digit_only_decimal_looking_blob() {
        assert!(!is_plausible_hex_task_token("172"));
        assert!(!is_plausible_hex_task_token("999"));
    }

    #[test]
    fn plausible_token_accepts_short_unpadded_with_hex_letters() {
        assert!(is_plausible_hex_task_token("2A"));
        assert!(is_plausible_hex_task_token("0xdead"));
    }

    #[test]
    fn correlation_equal_across_padding_case_and_prefix() {
        assert!(hex_correlation_tokens_equal("0000002A", "2a"));
        assert!(hex_correlation_tokens_equal("0x2A", "0000002A"));
        assert!(!hex_correlation_tokens_equal("12345678", "87654321"));
    }

    #[test]
    fn loot_match_from_metadata_only() {
        let meta = json!({"request_id": "2A"});
        assert!(loot_matches_expected_task_id("0000002A", None, Some(&meta)));
        let meta_tid = json!({"task_id": "0000002A"});
        assert!(loot_matches_expected_task_id("2a", None, Some(&meta_tid)));
        assert!(loot_matches_expected_task_id("2a", Some("0000002A"), None));
    }
}
