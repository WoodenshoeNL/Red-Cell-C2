use std::error::Error;

use super::super::PhantomAgent;
use super::super::run_loop::{is_within_working_hours_at, sleep_until_working_hours};
use super::{encode_working_hours, local_time};
use crate::config::PhantomConfig;

#[test]
fn compute_sleep_delay_honors_jitter_range() -> Result<(), Box<dyn Error>> {
    let config =
        PhantomConfig { sleep_delay_ms: 1_000, sleep_jitter: 20, ..PhantomConfig::default() };
    let agent = PhantomAgent::new(config)?;

    for _ in 0..128 {
        let delay = agent.compute_sleep_delay();
        assert!((800..=1_200).contains(&delay));
    }

    Ok(())
}

#[test]
fn compute_sleep_delay_returns_base_without_jitter() -> Result<(), Box<dyn Error>> {
    let config =
        PhantomConfig { sleep_delay_ms: 1_337, sleep_jitter: 0, ..PhantomConfig::default() };
    let agent = PhantomAgent::new(config)?;

    assert_eq!(agent.compute_sleep_delay(), 1_337);
    Ok(())
}

#[test]
fn compute_sleep_delay_waits_until_working_hours_resume() -> Result<(), Box<dyn Error>> {
    let config = PhantomConfig {
        sleep_delay_ms: 5_000,
        working_hours: Some(encode_working_hours(9, 0, 17, 0)),
        ..PhantomConfig::default()
    };
    let agent = PhantomAgent::new(config)?;
    let now = local_time(18, 30);

    assert!(!is_within_working_hours_at(agent.config.working_hours.unwrap_or_default(), now));
    assert_eq!(
        sleep_until_working_hours(agent.config.working_hours.unwrap_or_default(), now),
        52_200_000
    );
    Ok(())
}

#[test]
fn working_hours_allows_callback_during_window() {
    let now = local_time(9, 30);
    assert!(is_within_working_hours_at(encode_working_hours(9, 0, 17, 0), now));
}

#[test]
fn kill_date_elapsed_checks_state_kill_date() -> Result<(), Box<dyn Error>> {
    let mut agent = PhantomAgent::new(PhantomConfig::default())?;
    assert!(!agent.kill_date_elapsed());

    // Set a kill date in the past via state.
    agent.state.set_kill_date(Some(1));
    assert!(agent.kill_date_elapsed());

    // Disable it.
    agent.state.set_kill_date(None);
    assert!(!agent.kill_date_elapsed());
    Ok(())
}

#[test]
fn kill_date_elapsed_state_overrides_config() -> Result<(), Box<dyn Error>> {
    // Config has a kill date far in the future.
    let config = PhantomConfig { kill_date: Some(i64::MAX), ..PhantomConfig::default() };
    let mut agent = PhantomAgent::new(config)?;
    assert!(!agent.kill_date_elapsed());

    // State kill date in the past takes precedence.
    agent.state.set_kill_date(Some(1));
    assert!(agent.kill_date_elapsed());
    Ok(())
}
