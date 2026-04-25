//! Shared test harness and payload builders for assembly dispatch tests.

use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    SocketRelayManager, TeamserverState, build_router,
};
use red_cell_common::config::Profile;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use tokio::net::TcpListener;

// ── payload builders ────────────────────────────────────────────────────────

/// Build a BOF_CALLBACK_OUTPUT (0x00) payload: u32 LE type + length-prefixed UTF-8 string.
pub(super) fn bof_output_payload(text: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0u32.to_le_bytes()); // BOF_CALLBACK_OUTPUT
    p.extend_from_slice(&(text.len() as u32).to_le_bytes());
    p.extend_from_slice(text.as_bytes());
    p
}

/// Build a BOF_RAN_OK (3) payload: just the u32 LE sub-type, no extra data.
pub(super) fn bof_ran_ok_payload() -> Vec<u8> {
    3u32.to_le_bytes().to_vec()
}

/// Build a BOF_EXCEPTION (1) payload: u32 LE sub-type + u32 LE exception code + u64 LE address.
pub(super) fn bof_exception_payload(exception_code: u32, address: u64) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&1u32.to_le_bytes()); // BOF_EXCEPTION
    p.extend_from_slice(&exception_code.to_le_bytes());
    p.extend_from_slice(&address.to_le_bytes());
    p
}

/// Build a BOF_SYMBOL_NOT_FOUND (2) payload: u32 LE sub-type + length-prefixed UTF-8 symbol name.
pub(super) fn bof_symbol_not_found_payload(symbol: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&2u32.to_le_bytes()); // BOF_SYMBOL_NOT_FOUND
    p.extend_from_slice(&(symbol.len() as u32).to_le_bytes());
    p.extend_from_slice(symbol.as_bytes());
    p
}

/// Build a BOF_COULD_NOT_RUN (4) payload: just the u32 LE sub-type, no extra data.
pub(super) fn bof_could_not_run_payload() -> Vec<u8> {
    4u32.to_le_bytes().to_vec()
}

/// Build a BOF_CALLBACK_ERROR (0x0d) payload: u32 LE type + length-prefixed UTF-8 string.
pub(super) fn bof_callback_error_payload(text: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0x0du32.to_le_bytes()); // BOF_CALLBACK_ERROR
    p.extend_from_slice(&(text.len() as u32).to_le_bytes());
    p.extend_from_slice(text.as_bytes());
    p
}

/// Build an unknown BOF sub-type payload: u32 LE with a value that doesn't match any known variant.
pub(super) fn bof_unknown_subtype_payload(subtype: u32) -> Vec<u8> {
    subtype.to_le_bytes().to_vec()
}

/// Build a DOTNET_INFO_NET_VERSION (0x2) payload for `CommandAssemblyInlineExecute`.
/// The CLR version string is encoded as a LE-length-prefixed UTF-16 LE string.
pub(super) fn assembly_clr_version_payload(version: &str) -> Vec<u8> {
    let utf16_bytes: Vec<u8> = version.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let mut p = Vec::new();
    p.extend_from_slice(&2u32.to_le_bytes()); // DOTNET_INFO_NET_VERSION
    p.extend_from_slice(&(utf16_bytes.len() as u32).to_le_bytes());
    p.extend_from_slice(&utf16_bytes);
    p
}

/// Build a DOTNET_INFO_PATCHED (0x1) payload for `CommandAssemblyInlineExecute`.
/// No extra data beyond the u32 LE info-id.
pub(super) fn assembly_patched_payload() -> Vec<u8> {
    1u32.to_le_bytes().to_vec()
}

/// Build a DOTNET_INFO_ENTRYPOINT_EXECUTED (0x3) payload for `CommandAssemblyInlineExecute`.
/// Contains the info-id followed by a u32 LE thread ID.
pub(super) fn assembly_entrypoint_executed_payload(thread_id: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&3u32.to_le_bytes()); // DOTNET_INFO_ENTRYPOINT_EXECUTED
    p.extend_from_slice(&thread_id.to_le_bytes());
    p
}

/// Build a DOTNET_INFO_FINISHED (0x4) payload for `CommandAssemblyInlineExecute`.
/// No extra data beyond the u32 LE info-id.
pub(super) fn assembly_finished_payload() -> Vec<u8> {
    4u32.to_le_bytes().to_vec()
}

/// Build a DOTNET_INFO_FAILED (0x5) payload for `CommandAssemblyInlineExecute`.
/// No extra data beyond the u32 LE info-id.
pub(super) fn assembly_failed_payload() -> Vec<u8> {
    5u32.to_le_bytes().to_vec()
}

/// Build an unknown info-id payload for `CommandAssemblyInlineExecute`.
pub(super) fn assembly_unknown_info_id_payload(info_id: u32) -> Vec<u8> {
    info_id.to_le_bytes().to_vec()
}

/// Build a `CommandAssemblyListVersions` payload: a sequence of LE-length-prefixed
/// UTF-16 LE strings, one per version.
pub(super) fn assembly_list_versions_payload(versions: &[&str]) -> Vec<u8> {
    let mut p = Vec::new();
    for v in versions {
        let utf16_bytes: Vec<u8> = v.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        p.extend_from_slice(&(utf16_bytes.len() as u32).to_le_bytes());
        p.extend_from_slice(&utf16_bytes);
    }
    p
}

/// Build a `CommandPsImport` payload with a non-empty UTF-8 output string.
pub(super) fn ps_import_output_payload(text: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&(text.len() as u32).to_le_bytes());
    p.extend_from_slice(text.as_bytes());
    p
}

/// Build a `CommandPsImport` payload with an empty output string (zero-length).
pub(super) fn ps_import_empty_output_payload() -> Vec<u8> {
    0u32.to_le_bytes().to_vec()
}

// ── shared profile ───────────────────────────────────────────────────────────

pub(super) const PROFILE: &str = r#"
    Teamserver {
      Host = "127.0.0.1"
      Port = 0
    }

    Operators {
      user "operator" {
        Password = "password1234"
        Role = "Operator"
      }
    }

    Demon {}
"#;

/// Boot a teamserver and return its local address together with a cloned
/// `ListenerManager` so callers can start HTTP listeners.
pub(super) async fn start_server()
-> Result<(std::net::SocketAddr, ListenerManager), Box<dyn std::error::Error>> {
    let profile = Profile::parse(PROFILE)?;
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let listeners = ListenerManager::new(
        database.clone(),
        registry.clone(),
        events.clone(),
        sockets.clone(),
        None,
    )
    .with_demon_allow_legacy_ctr(true);
    let state = TeamserverState {
        profile: profile.clone(),
        profile_path: "test.yaotl".to_owned(),
        database: database.clone(),
        auth: AuthService::from_profile(&profile).expect("auth service should init"),
        api: ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
        events,
        connections: OperatorConnectionManager::new(),
        agent_registry: registry.clone(),
        listeners: listeners.clone(),
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets,
        webhooks: AuditWebhookNotifier::from_profile(&profile),
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: red_cell::ShutdownController::new(),
        service_bridge: None,
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: red_cell::metrics::standalone_metrics_handle(),
    };

    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let addr = tcp.local_addr()?;
    tokio::spawn(async move {
        let app = build_router(state);
        let _ = axum::serve(tcp, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await;
    });

    Ok((addr, listeners))
}

/// Register a fresh agent via DEMON_INIT and return the ctr_offset after init.
pub(super) async fn register_agent(
    client: &reqwest::Client,
    listener_port: u16,
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Result<u64, Box<dyn std::error::Error>> {
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(super::common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    // DEMON_INIT registers agents in legacy CTR mode — every packet starts at block 0.
    Ok(0)
}
