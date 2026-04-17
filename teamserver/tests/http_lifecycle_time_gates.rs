//! HTTP listener kill_date and working_hours enforcement tests.
//!
//! `kill_date` is enforced server-side — past dates must reject `DEMON_INIT`
//! while future dates must accept it.  `working_hours` is enforced on the
//! agent side (victim's local clock), so the teamserver must always accept
//! callbacks regardless of the configured window.

mod common;
mod listener_helpers;

use std::time::Duration;

use listener_helpers::{http_config_with_time, test_manager};
use tokio::time::timeout;

#[tokio::test]
async fn listener_with_past_kill_date_rejects_demon_init() -> Result<(), Box<dyn std::error::Error>>
{
    use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};

    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    // Set kill_date to 1 second in the past (unix timestamp).
    let past_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .saturating_sub(1);
    let kill_date_str = past_epoch.to_string();

    manager.create(http_config_with_time("lc-kill-past", port, Some(&kill_date_str), None)).await?;
    drop(guard);
    manager.start("lc-kill-past").await?;
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    // Attempt a DEMON_INIT — should be rejected (fake 404).
    let client = reqwest::Client::new();
    let agent_id: u32 = 0xDEAD_1001;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];
    let body = common::valid_demon_init_body(agent_id, key, iv);
    let resp = client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await?;

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "DEMON_INIT must be rejected when kill_date is in the past"
    );

    manager.stop("lc-kill-past").await?;
    Ok(())
}

#[tokio::test]
async fn listener_with_future_kill_date_accepts_demon_init()
-> Result<(), Box<dyn std::error::Error>> {
    use red_cell::demon::INIT_EXT_MONOTONIC_CTR;
    use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};

    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    // Set kill_date to 1 hour in the future.
    let future_epoch =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() + 3600;
    let kill_date_str = future_epoch.to_string();

    manager
        .create(http_config_with_time("lc-kill-future", port, Some(&kill_date_str), None))
        .await?;
    drop(guard);
    manager.start("lc-kill-future").await?;
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    // DEMON_INIT should succeed (200 OK with a body).
    let client = reqwest::Client::new();
    let agent_id: u32 = 0xDEAD_1002;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];
    let body =
        common::valid_demon_init_body_with_ext_flags(agent_id, key, iv, INIT_EXT_MONOTONIC_CTR);
    let resp = client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await?;

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "DEMON_INIT must succeed when kill_date is in the future"
    );
    let resp_body = resp.bytes().await?;
    assert!(!resp_body.is_empty(), "init ACK must have a non-empty body");

    manager.stop("lc-kill-future").await?;
    Ok(())
}

/// WorkingHours is enforced agent-side (victim's local clock), not server-side.
/// Verify that a listener with working_hours configured still accepts callbacks
/// regardless of the server's current time.
#[tokio::test]
async fn listener_working_hours_does_not_gate_server_side() -> Result<(), Box<dyn std::error::Error>>
{
    use red_cell::demon::INIT_EXT_MONOTONIC_CTR;
    use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};

    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    // Pick a working_hours window that definitely excludes the current UTC time.
    // The server must still accept the callback because enforcement is agent-side.
    let now_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let utc_hour = ((now_secs % 86400) / 3600) as u8;
    let excluded_start = (utc_hour + 12) % 24;
    let excluded_end = (excluded_start + 1) % 24;
    let (start, end) =
        if excluded_end > excluded_start { (excluded_start, excluded_end) } else { (5_u8, 6_u8) };
    let working_hours = format!("{start:02}:00-{end:02}:00");

    manager
        .create(http_config_with_time("lc-wh-no-gate", port, None, Some(&working_hours)))
        .await?;
    drop(guard);
    manager.start("lc-wh-no-gate").await?;
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    let client = reqwest::Client::new();
    let agent_id: u32 = 0xDEAD_2001;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];
    let body =
        common::valid_demon_init_body_with_ext_flags(agent_id, key, iv, INIT_EXT_MONOTONIC_CTR);
    let resp = client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await?;

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "DEMON_INIT must succeed even outside working hours ({working_hours}, UTC hour {utc_hour}) — enforcement is agent-side"
    );
    let resp_body = resp.bytes().await?;
    assert!(!resp_body.is_empty(), "init ACK must have a non-empty body");

    manager.stop("lc-wh-no-gate").await?;
    Ok(())
}
