//! Listener lifecycle management for the teamserver.
//!
//! This module is a thin facade: each concern lives in its own submodule.
//!
//! - [`manager`] — [`ListenerManager`] and its error type, CRUD, profile sync,
//!   TLS hot-reload, and per-protocol runtime spawning.
//! - [`summary`] — [`ListenerSummary`] and [`ListenerMarkRequest`] payload
//!   shapes used by REST and WebSocket responses.
//! - [`rate_limiters`] — sliding-window rate limiters shared across listener
//!   runtimes (Demon init, reconnect probe, unknown-callback audit, DNS recon).
//! - [`http`] / [`smb`] / [`dns`] / [`external`] — per-protocol runtimes and
//!   their helpers (including Demon transport processing and TLS watching).
//! - [`config`] — YAOTL-profile / operator-payload parsing for listener
//!   configurations.
//! - [`events`] — operator-event shapes and mark-action parsing.

mod config;
mod dns;
mod events;
mod external;
mod http;
mod manager;
mod rate_limiters;
mod smb;
mod summary;
#[cfg(test)]
mod tests;

pub use config::listener_config_from_operator;
pub use events::{
    ListenerEventAction, action_from_mark, listener_error_event, listener_event_for_action,
    listener_removed_event, operator_requests_start,
};
pub use external::{ExternalListenerState, handle_external_request};
pub use manager::{ListenerManager, ListenerManagerError};
pub use summary::{ListenerMarkRequest, ListenerSummary};

// Crate-visible re-exports consumed by other teamserver modules and by the
// sibling listener submodules (which reach through `super::`).
pub(crate) use http::{
    DemonHttpDisposition, DemonTransportKind, allow_demon_init_for_ip, classify_demon_transport,
    collect_body_with_magic_precheck, is_valid_demon_callback_request, process_demon_transport,
};
pub(crate) use manager::ListenerRuntimeFuture;
pub(crate) use rate_limiters::{
    DEMON_INIT_WINDOW_DURATION, DemonInitRateLimiter, DnsReconBlockLimiter,
    MAX_DEMON_INIT_ATTEMPTS_PER_IP, MAX_RECONNECT_PROBES_PER_AGENT,
    RECONNECT_PROBE_WINDOW_DURATION, ReconnectProbeRateLimiter, UnknownCallbackProbeAuditLimiter,
};

// Test-only re-exports: tests in `listeners::tests::*` reach these through
// `super::super::`, so they must live at the `listeners::` namespace. They are
// not part of the public API and stay behind `cfg(test)`.
#[cfg(test)]
pub(crate) use config::profile_listener_configs;
#[cfg(test)]
pub(crate) use manager::spawn_managed_listener_task;
#[cfg(test)]
pub(crate) use smb::spawn_smb_listener_runtime;

#[cfg(test)]
use crate::{ListenerStatus, dispatch::DownloadTracker};

#[cfg(test)]
pub(crate) use events::operator_protocol_name;
#[cfg(test)]
pub(crate) use http::{
    ProcessedDemonResponse, TrustedProxyPeer, build_response, cert_mtime, extract_external_ip,
    http_listener_subject_alt_names, is_past_kill_date, map_command_dispatch_error,
    parse_trusted_proxy_peer, reload_tls_from_files, set_default_header, spawn_cert_file_watcher,
};
#[cfg(test)]
pub(crate) use rate_limiters::{
    DNS_RECON_WINDOW_DURATION, MAX_DEMON_INIT_ATTEMPT_WINDOWS, MAX_DNS_RECON_QUERIES_PER_IP,
    MAX_RECONNECT_PROBE_WINDOWS, MAX_UNKNOWN_CALLBACK_PROBE_AUDITS_PER_SOURCE,
    UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOW_DURATION,
};
#[cfg(test)]
use smb::{MAX_SMB_FRAME_PAYLOAD_LEN, read_smb_frame};

#[cfg(test)]
use crate::MAX_AGENT_MESSAGE_LEN;
