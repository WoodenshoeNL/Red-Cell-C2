//! SMB named-pipe C2 listener transport.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use interprocess::local_socket::tokio::Stream as LocalSocketStream;
use interprocess::local_socket::traits::tokio::Listener as _;
use interprocess::local_socket::{ListenerOptions, ToFsName as _, ToNsName as _};
#[cfg(unix)]
use interprocess::os::unix::local_socket::{AbstractNsUdSocket, FilesystemUdSocket};
#[cfg(windows)]
use interprocess::os::windows::local_socket::NamedPipe;
use red_cell_common::SmbListenerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::warn;

use super::{
    DEMON_INIT_WINDOW_DURATION, DemonInitRateLimiter, ListenerManagerError, ListenerRuntimeFuture,
    MAX_DEMON_INIT_ATTEMPTS_PER_IP, ReconnectProbeRateLimiter, UnknownCallbackProbeAuditLimiter,
    classify_demon_transport, is_valid_demon_callback_request, process_demon_transport,
};
use crate::dispatch::DownloadTracker;
use crate::events::EventBus;
use crate::rate_limiter::AttemptWindow;
use crate::{
    AgentRegistry, CommandDispatcher, Database, DemonInitSecretConfig, DemonPacketParser,
    PluginRuntime, ShutdownController, SocketRelayManager,
};

use super::{DemonHttpDisposition, DemonTransportKind};

const SMB_PIPE_PREFIX: &str = r"\\.\pipe\";
pub(super) const MAX_SMB_FRAME_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub(super) struct SmbListenerState {
    config: SmbListenerConfig,
    registry: AgentRegistry,
    database: Database,
    parser: DemonPacketParser,
    events: EventBus,
    dispatcher: CommandDispatcher,
    unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
    reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
    demon_init_rate_limiter: DemonInitRateLimiter,
    shutdown: ShutdownController,
}

impl SmbListenerState {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build(
        config: &SmbListenerConfig,
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
        sockets: SocketRelayManager,
        plugins: Option<PluginRuntime>,
        downloads: DownloadTracker,
        unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
        reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
        demon_init_rate_limiter: DemonInitRateLimiter,
        shutdown: ShutdownController,
        init_secret_config: DemonInitSecretConfig,
        max_pivot_chain_depth: usize,
        allow_legacy_ctr: bool,
    ) -> Self {
        Self {
            config: config.clone(),
            registry: registry.clone(),
            database: database.clone(),
            parser: DemonPacketParser::with_init_secret_config(
                registry.clone(),
                init_secret_config.clone(),
            )
            .with_allow_legacy_ctr(allow_legacy_ctr),
            events: events.clone(),
            unknown_callback_probe_audit_limiter,
            reconnect_probe_rate_limiter,
            demon_init_rate_limiter,
            shutdown,
            dispatcher: CommandDispatcher::with_builtin_handlers_and_downloads(
                registry.clone(),
                events.clone(),
                database,
                sockets,
                plugins,
                downloads,
                max_pivot_chain_depth,
                allow_legacy_ctr,
                init_secret_config,
            ),
        }
    }
}

/// Sliding-window admission for full `DEMON_INIT` registrations on a single SMB named-pipe
/// connection.  Unlike HTTP/DNS/External, SMB has no trustworthy remote IP; the only stable
/// transport identity is the connection itself, so we key the limiter here instead of using a
/// synthetic IPv4 derived from `agent_id` (which an attacker could rotate to bypass throttling).
async fn allow_demon_init_for_smb_connection(
    listener_name: &str,
    window: &Mutex<AttemptWindow>,
    body: &[u8],
) -> bool {
    if classify_demon_transport(body) != Some(DemonTransportKind::Init) {
        return true;
    }

    let mut w = window.lock().await;
    let now = Instant::now();
    if now.duration_since(w.window_start) >= DEMON_INIT_WINDOW_DURATION {
        w.attempts = 0;
        w.window_start = now;
    }
    if w.attempts >= MAX_DEMON_INIT_ATTEMPTS_PER_IP {
        warn!(
            listener = listener_name,
            max_attempts = MAX_DEMON_INIT_ATTEMPTS_PER_IP,
            window_seconds = DEMON_INIT_WINDOW_DURATION.as_secs(),
            "rejecting DEMON_INIT because the per-SMB-connection rate limit was exceeded"
        );
        return false;
    }
    w.attempts += 1;
    true
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_smb_listener_runtime(
    config: &SmbListenerConfig,
    registry: AgentRegistry,
    events: EventBus,
    database: Database,
    sockets: SocketRelayManager,
    plugins: Option<PluginRuntime>,
    downloads: DownloadTracker,
    unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
    reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
    demon_init_rate_limiter: DemonInitRateLimiter,
    shutdown: ShutdownController,
    init_secret_config: DemonInitSecretConfig,
    max_pivot_chain_depth: usize,
    allow_legacy_ctr: bool,
) -> Result<ListenerRuntimeFuture, ListenerManagerError> {
    let state = Arc::new(SmbListenerState::build(
        config,
        registry,
        events,
        database,
        sockets,
        plugins,
        downloads,
        unknown_callback_probe_audit_limiter,
        reconnect_probe_rate_limiter,
        demon_init_rate_limiter,
        shutdown,
        init_secret_config,
        max_pivot_chain_depth,
        allow_legacy_ctr,
    ));
    let listener_name = normalized_smb_pipe_name(&config.pipe_name);
    let socket_name = smb_local_socket_name(&config.pipe_name).map_err(|error| {
        ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!("failed to resolve SMB pipe `{listener_name}`: {error}"),
        }
    })?;
    let listener = ListenerOptions::new().name(socket_name).create_tokio().map_err(|error| {
        ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!("failed to bind SMB pipe `{listener_name}`: {error}"),
        }
    })?;

    Ok(Box::pin(async move {
        let shutdown_signal = state.shutdown.notified();
        tokio::pin!(shutdown_signal);

        loop {
            tokio::select! {
                _ = &mut shutdown_signal => return Ok(()),
                accept = listener.accept() => {
                    match accept {
                        Ok(stream) => {
                            let state = state.clone();
                            tokio::spawn(async move {
                                handle_smb_connection(state, stream).await;
                            });
                        }
                        Err(error) => {
                            return Err(format!(
                                "smb listener `{}` on pipe `{listener_name}` exited: {error}",
                                state.config.name
                            ));
                        }
                    }
                }
            }
        }
    }))
}

async fn handle_smb_connection(state: Arc<SmbListenerState>, mut stream: LocalSocketStream) {
    let demon_init_window = Mutex::new(AttemptWindow::default());
    loop {
        if state.shutdown.is_shutting_down() {
            break;
        }

        let frame = match read_smb_frame(&mut stream).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) => {
                warn!(listener = %state.config.name, %error, "failed to read smb frame");
                break;
            }
        };

        if !is_valid_demon_callback_request(&frame.payload) {
            warn!(
                listener = %state.config.name,
                agent_id = format_args!("{:08X}", frame.agent_id),
                "ignoring invalid smb demon frame"
            );
            continue;
        }

        let Some(_callback_guard) = state.shutdown.try_track_callback() else {
            break;
        };

        // SMB runs over a local named pipe — no trustworthy remote IP.  Keep operator-facing
        // `external_ip` as a deterministic IPv4 derived from `agent_id` (Havoc-compatible),
        // but rate-limit full DEMON_INIT registrations per named-pipe connection (not per
        // attacker-chosen agent_id).
        let client_ip = IpAddr::V4(Ipv4Addr::from(frame.agent_id.to_be_bytes()));
        if !allow_demon_init_for_smb_connection(
            &state.config.name,
            &demon_init_window,
            &frame.payload,
        )
        .await
        {
            continue;
        }

        match process_demon_transport(
            &state.config.name,
            &state.registry,
            &state.database,
            &state.parser,
            &state.events,
            &state.dispatcher,
            &state.unknown_callback_probe_audit_limiter,
            &state.reconnect_probe_rate_limiter,
            &state.demon_init_rate_limiter,
            &frame.payload,
            client_ip.to_string(),
        )
        .await
        {
            Ok(response) => {
                if response.http_disposition == DemonHttpDisposition::Fake404
                    || response.http_disposition == DemonHttpDisposition::TooManyRequests
                {
                    continue;
                }

                if let Err(error) =
                    write_smb_frame(&mut stream, response.agent_id, &response.payload).await
                {
                    warn!(
                        listener = %state.config.name,
                        agent_id = format_args!("{:08X}", response.agent_id),
                        %error,
                        "failed to write smb response"
                    );
                    break;
                }
            }
            Err(error) => {
                warn!(
                    listener = %state.config.name,
                    agent_id = format_args!("{:08X}", frame.agent_id),
                    %error,
                    "failed to process smb demon frame"
                );
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct SmbFrame {
    pub(super) agent_id: u32,
    pub(super) payload: Vec<u8>,
}

pub(super) async fn read_smb_frame(stream: &mut LocalSocketStream) -> io::Result<Option<SmbFrame>> {
    let agent_id = match stream.read_u32_le().await {
        Ok(agent_id) => agent_id,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    let payload_len = match stream.read_u32_le().await {
        Ok(length) => length,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    let payload_len = usize::try_from(payload_len).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "smb frame payload length overflowed usize")
    })?;
    if payload_len > MAX_SMB_FRAME_PAYLOAD_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "smb frame payload length {payload_len} exceeds maximum of {MAX_SMB_FRAME_PAYLOAD_LEN} bytes"
            ),
        ));
    }
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload).await?;
    Ok(Some(SmbFrame { agent_id, payload }))
}

async fn write_smb_frame(
    stream: &mut LocalSocketStream,
    agent_id: u32,
    payload: &[u8],
) -> io::Result<()> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "smb frame payload exceeds u32 length")
    })?;
    stream.write_u32_le(agent_id).await?;
    stream.write_u32_le(payload_len).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

/// Normalise an SMB pipe name, adding the Windows `\\.\pipe\` prefix when needed.
pub(super) fn normalized_smb_pipe_name(pipe_name: &str) -> String {
    let trimmed = pipe_name.trim();
    if trimmed.starts_with('/') || trimmed.starts_with(r"\\") {
        trimmed.to_owned()
    } else {
        format!("{SMB_PIPE_PREFIX}{trimmed}")
    }
}

#[cfg(unix)]
pub(super) fn smb_local_socket_name(
    pipe_name: &str,
) -> io::Result<interprocess::local_socket::Name<'static>> {
    if pipe_name.trim_start().starts_with('/') {
        pipe_name.to_fs_name::<FilesystemUdSocket>().map(|name| name.into_owned())
    } else {
        normalized_smb_pipe_name(pipe_name)
            .to_ns_name::<AbstractNsUdSocket>()
            .map(|name| name.into_owned())
    }
}

#[cfg(windows)]
pub(super) fn smb_local_socket_name(
    pipe_name: &str,
) -> io::Result<interprocess::local_socket::Name<'static>> {
    normalized_smb_pipe_name(pipe_name).to_fs_name::<NamedPipe>().map(|name| name.into_owned())
}
