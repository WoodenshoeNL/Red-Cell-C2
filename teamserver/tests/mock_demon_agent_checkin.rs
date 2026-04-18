//! Mock Demon agent checkin integration tests.
//!
//! These tests spin up a real HTTP C2 listener through the [`ListenerManager`] API,
//! send mock Demon agent packets as HTTP POST requests, and verify the full flow:
//! agent init → registration → task delivery → callback → operator event.
//!
//! Modules:
//! - `helpers`        — shared test harness and utilities
//! - `init`           — basic init, output delivery, idle-poll, and multi-agent tests
//! - `auth`           — operator auth rejection and malformed message tests
//! - `reconnect`      — reconnect protocol and CTR synchronisation tests
//! - `seq_protection` — wrong-key rejection and duplicate-init protection tests
//! - `legacy_ctr`     — legacy CTR mode behaviour tests

mod common;

#[path = "mock_demon_agent_checkin/helpers.rs"]
mod helpers;

#[path = "mock_demon_agent_checkin/auth.rs"]
mod auth;
#[path = "mock_demon_agent_checkin/init.rs"]
mod init;
#[path = "mock_demon_agent_checkin/legacy_ctr.rs"]
mod legacy_ctr;
#[path = "mock_demon_agent_checkin/reconnect.rs"]
mod reconnect;
#[path = "mock_demon_agent_checkin/seq_protection.rs"]
mod seq_protection;
