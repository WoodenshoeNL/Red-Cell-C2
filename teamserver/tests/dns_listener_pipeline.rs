//! DNS listener integration tests.
//!
//! These tests spin up a real DNS C2 listener through the [`ListenerManager`] API,
//! send mock Demon agent packets as UDP DNS queries, and verify the full flow:
//! agent init → registration → callback → response.  They follow the same pattern
//! as `http_listener_pipeline.rs` and `smb_listener.rs`.
//!
//! Modules:
//! - `helpers`  — shared test utilities (packet builders, port allocation, upload/download)
//! - `init`     — agent registration and re-init tests
//! - `malformed`— malformed/truncated packet rejection and listener resilience tests
//! - `callback` — callback, task delivery, out-of-order, and concurrent session tests
//! - `doh`      — Specter/Archon DoH grammar tests (RFC 4648 base32, NXDOMAIN ack)

mod common;

#[path = "dns_listener_pipeline/helpers.rs"]
mod helpers;

#[path = "dns_listener_pipeline/callback.rs"]
mod callback;
#[path = "dns_listener_pipeline/doh.rs"]
mod doh;
#[path = "dns_listener_pipeline/init.rs"]
mod init;
#[path = "dns_listener_pipeline/malformed.rs"]
mod malformed;
