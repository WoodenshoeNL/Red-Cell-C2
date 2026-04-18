//! End-to-end integration tests for the operator WebSocket ↔ agent session lifecycle.
//!
//! Modules:
//! - `helpers`   — shared profiles, message builders, DNS/SMB helpers
//! - `session`   — HTTP listener round-trip, reconnect probe, multi-operator fan-out
//! - `agent_ops` — SMB and DNS listener round-trip tests
//! - `auth`      — RBAC enforcement, auth rejection, and rate-limiter tests

mod common;

#[path = "e2e_operator_agent_session/helpers.rs"]
mod helpers;

#[path = "e2e_operator_agent_session/session.rs"]
mod session;

#[path = "e2e_operator_agent_session/agent_ops.rs"]
mod agent_ops;

#[path = "e2e_operator_agent_session/auth.rs"]
mod auth;
