//! Working-hours and kill-date time helpers.

use time::{OffsetDateTime, Time};

pub(super) fn current_local_time() -> OffsetDateTime {
    OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc())
}

pub(super) fn unpack_working_hours_time(
    working_hours: u32,
    hour_shift: u32,
    minute_shift: u32,
) -> Time {
    let hour = ((working_hours >> hour_shift) & 0b01_1111) as u8;
    let minute = ((working_hours >> minute_shift) & 0b11_1111) as u8;
    Time::from_hms(hour.min(23), minute.min(59), 0).unwrap_or(Time::MIDNIGHT)
}

pub(super) fn is_within_working_hours_at(working_hours: i32, now: OffsetDateTime) -> bool {
    let working_hours = working_hours as u32;
    if (working_hours >> 22) & 1 == 0 {
        return true;
    }

    let start = unpack_working_hours_time(working_hours, 17, 11);
    let end = unpack_working_hours_time(working_hours, 6, 0);
    let current = now.time();

    if current.hour() < start.hour() || current.hour() > end.hour() {
        return false;
    }
    if current.hour() == start.hour() && current.minute() < start.minute() {
        return false;
    }
    if current.hour() == end.hour() && current.minute() > end.minute() {
        return false;
    }

    true
}

pub(super) fn sleep_until_working_hours(working_hours: i32, now: OffsetDateTime) -> u64 {
    let working_hours = working_hours as u32;
    let start = unpack_working_hours_time(working_hours, 17, 11);
    let end = unpack_working_hours_time(working_hours, 6, 0);
    let current_minutes = u64::from(now.hour()) * 60 + u64::from(now.minute());
    let start_minutes = u64::from(start.hour()) * 60 + u64::from(start.minute());
    let end_minutes = u64::from(end.hour()) * 60 + u64::from(end.minute());

    let minutes_until_start = if current_minutes > end_minutes {
        ((24 * 60) - current_minutes) + start_minutes
    } else {
        start_minutes.saturating_sub(current_minutes)
    };
    minutes_until_start.saturating_mul(60_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_time(hour: u8, minute: u8) -> OffsetDateTime {
        let date =
            time::Date::from_calendar_date(2026, time::Month::January, 15).expect("valid date");
        let time = Time::from_hms(hour, minute, 0).expect("valid time");
        date.with_time(time).assume_utc()
    }

    fn pack_working_hours(start_h: u32, start_m: u32, end_h: u32, end_m: u32) -> i32 {
        let enabled = 1u32 << 22;
        let start = (start_h & 0x1F) << 17 | (start_m & 0x3F) << 11;
        let end = (end_h & 0x1F) << 6 | (end_m & 0x3F);
        (enabled | start | end) as i32
    }

    #[test]
    fn working_hours_disabled_returns_true() {
        let wh = 0i32; // bit 22 not set → disabled
        assert!(is_within_working_hours_at(wh, make_time(3, 0)));
    }

    #[test]
    fn within_working_hours_at_midpoint() {
        let wh = pack_working_hours(9, 0, 17, 0);
        assert!(is_within_working_hours_at(wh, make_time(12, 0)));
    }

    #[test]
    fn within_working_hours_at_start_boundary() {
        let wh = pack_working_hours(9, 0, 17, 0);
        assert!(is_within_working_hours_at(wh, make_time(9, 0)));
    }

    #[test]
    fn within_working_hours_at_end_boundary() {
        let wh = pack_working_hours(9, 0, 17, 0);
        assert!(is_within_working_hours_at(wh, make_time(17, 0)));
    }

    #[test]
    fn outside_working_hours_before_start() {
        let wh = pack_working_hours(9, 0, 17, 0);
        assert!(!is_within_working_hours_at(wh, make_time(8, 59)));
    }

    #[test]
    fn outside_working_hours_after_end() {
        let wh = pack_working_hours(9, 0, 17, 0);
        assert!(!is_within_working_hours_at(wh, make_time(17, 1)));
    }

    #[test]
    fn sleep_until_working_hours_before_start() {
        let wh = pack_working_hours(9, 0, 17, 0);
        let now = make_time(7, 0); // 2 hours before start
        let delay_ms = sleep_until_working_hours(wh, now);
        assert_eq!(delay_ms, 120 * 60_000); // 120 minutes
    }

    #[test]
    fn sleep_until_working_hours_after_end() {
        let wh = pack_working_hours(9, 0, 17, 0);
        let now = make_time(18, 0); // 1 hour after end → wraps to next day's start
        // 18:00 → next 09:00 = 15 hours = 900 minutes
        let delay_ms = sleep_until_working_hours(wh, now);
        assert_eq!(delay_ms, 900 * 60_000);
    }

    #[test]
    fn unpack_working_hours_time_extracts_correctly() {
        let wh = pack_working_hours(9, 30, 17, 45) as u32;
        let start = unpack_working_hours_time(wh, 17, 11);
        let end = unpack_working_hours_time(wh, 6, 0);
        assert_eq!(start.hour(), 9);
        assert_eq!(start.minute(), 30);
        assert_eq!(end.hour(), 17);
        assert_eq!(end.minute(), 45);
    }
}
