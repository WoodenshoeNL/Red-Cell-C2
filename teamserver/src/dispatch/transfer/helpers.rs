//! Formatting helpers shared by transfer list/control handlers.

pub(super) fn transfer_progress_text(progress: u64, total: u64) -> String {
    if total == 0 {
        return "0.00%".to_owned();
    }

    format!("{:.2}%", (progress as f64 / total as f64) * 100.0)
}

pub(super) fn transfer_state_name(state: u32) -> &'static str {
    match state {
        1 => "Running",
        2 => "Stopped",
        3 => "Removed",
        _ => "Unknown",
    }
}

pub(in crate::dispatch) fn byte_count(size: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut value = size as f64;
    let mut unit = 0usize;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{size} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}
