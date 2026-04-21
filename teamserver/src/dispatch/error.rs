use thiserror::Error;

use red_cell_common::demon::DemonProtocolError;

use crate::TeamserverError;

/// Error returned while routing or executing a Demon command handler.
#[derive(Debug, Error)]
pub enum CommandDispatchError {
    /// The dispatcher could not update shared teamserver state.
    #[error("{0}")]
    Registry(#[from] TeamserverError),
    /// A handler failed to serialize its response in Havoc's package format.
    #[error("failed to serialize demon response: {0}")]
    Protocol(#[from] DemonProtocolError),
    /// The dispatcher could not format a callback timestamp.
    #[error("failed to format callback timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
    /// A callback payload could not be parsed according to the Havoc wire format.
    #[error("failed to parse callback payload for command 0x{command_id:08X}: {message}")]
    InvalidCallbackPayload {
        /// Raw command identifier associated with the callback.
        command_id: u32,
        /// Human-readable parser error.
        message: String,
    },
    /// A download exceeded the configured in-memory accumulation cap and was dropped.
    #[error(
        "download 0x{file_id:08X} for agent 0x{agent_id:08X} exceeded max_download_bytes ({max_download_bytes} bytes)"
    )]
    DownloadTooLarge {
        /// Agent owning the dropped download.
        agent_id: u32,
        /// File identifier associated with the dropped download.
        file_id: u32,
        /// Configured maximum number of bytes allowed in memory for a single download.
        max_download_bytes: usize,
    },
    /// Active partial downloads exceeded the configured aggregate in-memory cap and one was dropped.
    #[error(
        "active downloads for agent 0x{agent_id:08X} exceeded aggregate max_download_bytes ({max_total_download_bytes} bytes) while tracking file 0x{file_id:08X}"
    )]
    DownloadAggregateTooLarge {
        /// Agent owning the dropped download.
        agent_id: u32,
        /// File identifier associated with the dropped download.
        file_id: u32,
        /// Configured maximum number of bytes allowed in memory across all active downloads.
        max_total_download_bytes: usize,
    },
    /// A new download start was rejected because the per-agent concurrent-download cap was reached.
    #[error(
        "agent 0x{agent_id:08X} already has {max_concurrent} concurrent downloads in progress; rejecting new download 0x{file_id:08X}"
    )]
    DownloadConcurrentLimitExceeded {
        /// Agent that attempted to open a new download.
        agent_id: u32,
        /// File identifier from the rejected start request.
        file_id: u32,
        /// Configured maximum number of concurrent in-progress downloads allowed per agent.
        max_concurrent: usize,
    },
    /// A pivot command callback was nested deeper than `MAX_PIVOT_CHAIN_DEPTH`.
    #[error(
        "pivot dispatch depth {depth} exceeds maximum ({max_depth}); possible recursive envelope attack"
    )]
    PivotDispatchDepthExceeded {
        /// The depth that was rejected.
        depth: usize,
        /// The configured maximum allowed depth.
        max_depth: usize,
    },
    /// No handler is registered for the command identifier carried by the callback.
    #[error(
        "no handler registered for command 0x{command_id:08X} from agent 0x{agent_id:08X} (request 0x{request_id:08X})"
    )]
    UnknownCommand {
        /// Agent that sent the callback.
        agent_id: u32,
        /// Unrecognised command identifier.
        command_id: u32,
        /// Request identifier from the callback header.
        request_id: u32,
    },
}
