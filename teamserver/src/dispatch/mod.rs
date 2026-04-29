//! Command routing for parsed Demon callback packages.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use red_cell_common::demon::DemonProtocolError;

use crate::DEFAULT_MAX_DOWNLOAD_BYTES;
use crate::{
    AgentRegistry, DemonCallbackPackage, DemonInitSecretConfig, EventBus, PluginRuntime,
    SocketRelayManager,
};

mod assembly;
mod checkin;
mod context;
mod dispatcher;
mod dispatcher_registration;
mod dispatcher_registration_commands;
mod dispatcher_registration_io;
mod dispatcher_runtime;
mod download;
mod error;
mod filesystem;
mod harvest;
mod kerberos;
mod network;
mod output;
mod pivot;
mod process;
mod response;
mod screenshot;
mod socket;
mod token;
mod transfer;
pub(crate) mod util;

pub use error::CommandDispatchError;

// `DownloadTracker` is also used from `listeners/`, so it needs crate-level visibility.
pub(crate) use download::DownloadTracker;

pub(crate) use context::DEFAULT_MAX_PIVOT_CHAIN_DEPTH;

// Flatten the context types and constants into this module's namespace so submodules
// can reach them via `super::Foo`.  None of these are used directly within mod.rs itself —
// `BuiltinDispatchContext` and `BuiltinHandlerDependencies` are accessed by `dispatcher.rs`,
// and the `DOTNET_INFO_*` constants are accessed by `assembly.rs`, all via `super::`.
#[allow(unused_imports)]
use context::{
    BuiltinDispatchContext, BuiltinHandlerDependencies, DOTNET_INFO_ENTRYPOINT_EXECUTED,
    DOTNET_INFO_FAILED, DOTNET_INFO_FINISHED, DOTNET_INFO_NET_VERSION, DOTNET_INFO_PATCHED,
};

// Bring all remaining shared types into this module's namespace so submodules can
// reach them via `super::Foo`.  These imports are not used directly within mod.rs
// itself — they exist to flatten the namespace for child modules.
#[allow(unused_imports)]
use download::{DOWNLOAD_TRACKER_AGGREGATE_CAP_MULTIPLIER, DownloadState};
#[allow(unused_imports)]
use response::{
    AgentResponseEntry, CredentialCapture, LootContext, agent_response_event,
    agent_response_event_with_extra, agent_response_event_with_extra_and_context,
    agent_response_extra, bool_string, broadcast_and_persist_agent_response,
    broadcast_credential_event, extract_credentials, insert_loot_record, job_state_name,
    job_type_name, looks_like_credential_line, looks_like_inline_secret, looks_like_pwdump_hash,
    loot_context, loot_new_event, metadata_with_context, non_empty_option,
    parse_optional_kill_date, persist_agent_response_record, persist_credentials_from_output,
};
#[allow(unused_imports)]
use util::CallbackParser;

/// Byte order used by the agent for inner callback payload fields.
///
/// Demon (legacy Havoc C/ASM) encodes u32/u64 fields as big-endian.
/// Phantom and Specter (Rust agents) encode as little-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PayloadEndian {
    Le,
    Be,
}

tokio::task_local! {
    pub(crate) static PAYLOAD_ENDIAN: PayloadEndian;
}

type HandlerFuture =
    Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, CommandDispatchError>> + Send>>;
type Handler = dyn Fn(u32, u32, Vec<u8>) -> HandlerFuture + Send + Sync + 'static;

/// Central registry of Demon command handlers keyed by command identifier.
#[derive(Clone)]
pub struct CommandDispatcher {
    handlers: Arc<HashMap<u32, Arc<Handler>>>,
    pub(in crate::dispatch) downloads: DownloadTracker,
}

impl std::fmt::Debug for CommandDispatcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut commands = self.handlers.keys().copied().collect::<Vec<_>>();
        commands.sort_unstable();
        formatter.debug_struct("CommandDispatcher").field("registered_commands", &commands).finish()
    }
}

impl Default for CommandDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
