//! Kill-date parsing and validation helpers.

use crate::error::CommonError;

/// Parse a kill-date string into a Unix timestamp.
///
/// Accepts two representations:
/// 1. A plain decimal integer (unix timestamp).
/// 2. A human-readable datetime `"YYYY-MM-DD HH:MM:SS"` (interpreted as UTC).
///
/// Returns [`CommonError::InvalidKillDate`] for any other format.
pub fn parse_kill_date_to_epoch(value: &str) -> Result<i64, CommonError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(CommonError::InvalidKillDate { value: value.to_string() });
    }

    // Try plain integer first (fast path).
    if let Ok(ts) = value.parse::<i64>() {
        return Ok(ts);
    }

    // Try human-readable datetime "YYYY-MM-DD HH:MM:SS" (UTC).
    let format = time::format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second]")
        .map_err(|_| CommonError::InvalidKillDate { value: value.to_string() })?;
    let dt = time::PrimitiveDateTime::parse(value, &format)
        .map_err(|_| CommonError::InvalidKillDate { value: value.to_string() })?;
    Ok(dt.assume_utc().unix_timestamp())
}

/// Validate and normalise an optional KillDate value.
///
/// If the input is `None` or an empty/whitespace-only string, returns `Ok(None)`.
/// Otherwise parses the value (accepting both formats described in
/// [`parse_kill_date_to_epoch`]) and returns the normalised unix-timestamp string.
///
/// This should be called at config ingress (profile parsing and operator
/// requests) so that downstream consumers always receive a numeric timestamp
/// string.
pub fn validate_kill_date(value: Option<&str>) -> Result<Option<String>, CommonError> {
    let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let epoch = parse_kill_date_to_epoch(raw)?;
    Ok(Some(epoch.to_string()))
}
