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
    // Require at least one side to be unambiguously a hex task token so that a
    // decimal-looking SQLite row surrogate ("172", "999") cannot match a
    // coincidentally equal hex value.  An 8-char padded token on one side is
    // enough to anchor the comparison; the other side may be unpadded and
    // digit-only (e.g. "10" for 0x00000010).
    match (parse_hex_u32_trimmed(a), parse_hex_u32_trimmed(b)) {
        (Some(na), Some(nb)) if na == nb => {
            is_plausible_hex_task_token(a) || is_plausible_hex_task_token(b)
        }
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
        let candidate: Option<String> = match obj.get(key) {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Number(n)) => n.as_u64().and_then(|v| {
                // Only coerce numbers that fit in a u32 Demon request id.
                if v <= u32::MAX as u64 { Some(format!("{v:x}")) } else { None }
            }),
            _ => None,
        };
        if let Some(s) = candidate {
            if hex_correlation_tokens_equal(expected, &s) {
                return true;
            }
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
    fn correlation_accepts_padded_vs_digit_only_unpadded() {
        // 8-char padded token on one side anchors the comparison; the other side
        // may be unpadded and digit-only (regression: previously returned false).
        assert!(hex_correlation_tokens_equal("00000010", "10"));
        assert!(hex_correlation_tokens_equal("10", "00000010"));
        // Two digit-only strings with different hex values must not match.
        assert!(!hex_correlation_tokens_equal("00000010", "172"));
        // The decimal-looking rejects still hold in isolation.
        assert!(!is_plausible_hex_task_token("172"));
        assert!(!is_plausible_hex_task_token("999"));
    }

    #[test]
    fn loot_match_from_metadata_only() {
        let meta = json!({"request_id": "2A"});
        assert!(loot_matches_expected_task_id("0000002A", None, Some(&meta)));
        let meta_tid = json!({"task_id": "0000002A"});
        assert!(loot_matches_expected_task_id("2a", None, Some(&meta_tid)));
        assert!(loot_matches_expected_task_id("2a", Some("0000002A"), None));
    }

    #[test]
    fn loot_match_numeric_request_id() {
        // Numeric 42 (0x2A) should match string "0000002A".
        let meta = json!({"request_id": 42u32});
        assert!(loot_matches_expected_task_id("0000002A", None, Some(&meta)));
        // Numeric task_id variant.
        let meta_tid = json!({"task_id": 42u32});
        assert!(loot_matches_expected_task_id("2a", None, Some(&meta_tid)));
    }

    #[test]
    fn loot_match_numeric_padded_task_id() {
        // 0xDEADBEEF as a number should match the padded hex string.
        let meta = json!({"task_id": 0xDEAD_BEEFu32});
        assert!(loot_matches_expected_task_id("DEADBEEF", None, Some(&meta)));
    }

    #[test]
    fn loot_match_numeric_too_large_ignored() {
        // Values that exceed u32::MAX must not match anything.
        let meta = json!({"request_id": 0x1_0000_0000u64});
        assert!(!loot_matches_expected_task_id("00000001", None, Some(&meta)));
    }

    #[test]
    fn loot_match_numeric_mismatch_does_not_false_positive() {
        // Numeric 0x10 should not match 0x11.
        let meta = json!({"request_id": 0x10u32});
        assert!(!loot_matches_expected_task_id("00000011", None, Some(&meta)));
    }
}
