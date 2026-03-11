use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use clap::Parser;
use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, DEFAULT_MAX_REGISTERED_AGENTS,
    Database, EventBus, ListenerManager, ListenerManagerError, LoginRateLimiter,
    OperatorConnectionManager, PayloadBuilderService, PluginRuntime, SocketRelayManager,
    TeamserverState, build_router,
};
use red_cell_common::config::{Profile, ProfileValidationError};
use red_cell_common::tls::{
    TlsKeyAlgorithm, install_default_crypto_provider, resolve_tls_identity,
};
use tokio::net::lookup_host;
use tracing::{info, instrument};

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

mod logging;

#[derive(Debug, Clone, Parser)]
#[command(name = "red-cell", about = "Red Cell teamserver")]
struct Cli {
    /// Path to the Havoc-compatible YAOTL profile.
    #[arg(long)]
    profile: PathBuf,
    /// Optional SQLite database path. Defaults to `<profile>.sqlite`.
    #[arg(long)]
    database: Option<PathBuf>,
    /// Enable debug-level logging.
    #[arg(long, default_value_t = false)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let profile = load_profile(&cli.profile)
        .with_context(|| format!("failed to load profile from {}", cli.profile.display()))?;
    let _logging_guard = logging::init_tracing(Some(&profile), cli.debug)
        .map_err(|error| anyhow!("failed to initialize tracing: {error}"))?;

    let database_path = resolve_database_path(&cli.profile, cli.database.as_ref());
    let database = Database::connect(&database_path)
        .await
        .with_context(|| format!("failed to open database {}", database_path.display()))?;
    let agent_registry = AgentRegistry::load_with_max_registered_agents(
        database.clone(),
        profile.teamserver.max_registered_agents.unwrap_or(DEFAULT_MAX_REGISTERED_AGENTS),
    )
    .await?;
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
    let plugins = PluginRuntime::initialize(
        database.clone(),
        agent_registry.clone(),
        events.clone(),
        sockets.clone(),
        profile.teamserver.plugins_dir.as_ref().map(PathBuf::from),
    )
    .await
    .context("failed to initialize embedded Python runtime")?;
    let listeners = ListenerManager::with_max_download_bytes(
        database.clone(),
        agent_registry.clone(),
        events.clone(),
        sockets.clone(),
        Some(plugins.clone()),
        profile.teamserver.max_download_bytes.unwrap_or(512 * 1024 * 1024),
    );
    plugins.attach_listener_manager(listeners.clone()).await;
    let payload_builder = PayloadBuilderService::from_profile(&profile)
        .context("failed to validate Demon build toolchain")?;

    listeners.sync_profile(&profile).await?;
    listeners.restore_running().await?;
    start_new_profile_listeners(&listeners, &profile).await?;
    let loaded_plugins = plugins.load_plugins().await.context("failed to load Python plugins")?;
    if !loaded_plugins.is_empty() {
        info!(count = loaded_plugins.len(), plugins = ?loaded_plugins, "loaded Python plugins");
    }

    let bind_addr = resolve_bind_addr(&profile).await?;
    install_default_crypto_provider();
    let tls_config = build_tls_config(&profile).await?;
    let router = build_router(TeamserverState {
        profile: profile.clone(),
        auth: AuthService::from_profile_with_database(&profile, &database).await?,
        database,
        api: ApiRuntime::from_profile(&profile),
        events,
        connections: OperatorConnectionManager::new(),
        agent_registry,
        sockets,
        listeners,
        payload_builder,
        webhooks: AuditWebhookNotifier::from_profile(&profile),
        login_rate_limiter: LoginRateLimiter::new(),
    });
    let handle = Handle::new();

    tokio::spawn(wait_for_shutdown_signal(handle.clone()));

    info!("starting teamserver on https://{bind_addr}");

    axum_server::bind_rustls(bind_addr, tls_config)
        .handle(handle)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("teamserver exited with an error")?;

    Ok(())
}

#[instrument(skip(configured), fields(profile_path = %profile.display(), configured_database = configured.as_ref().map(|path| path.display().to_string())))]
fn resolve_database_path(profile: &Path, configured: Option<&PathBuf>) -> PathBuf {
    configured.cloned().unwrap_or_else(|| {
        let mut path = profile.to_path_buf();
        path.set_extension("sqlite");
        path
    })
}

#[instrument(skip(path), fields(profile_path = %path.display()))]
fn load_profile(path: &PathBuf) -> Result<Profile> {
    let profile = Profile::from_file(path)?;
    profile.validate().map_err(invalid_profile)?;
    Ok(profile)
}

fn invalid_profile(error: ProfileValidationError) -> anyhow::Error {
    anyhow!(error)
}

async fn resolve_bind_addr(profile: &Profile) -> Result<SocketAddr> {
    let mut addrs = lookup_host((profile.teamserver.host.as_str(), profile.teamserver.port))
        .await
        .with_context(|| {
            format!(
                "failed to resolve bind address {}:{}",
                profile.teamserver.host, profile.teamserver.port
            )
        })?;

    addrs.next().ok_or_else(|| {
        anyhow!(
            "no socket addresses resolved for {}:{}",
            profile.teamserver.host,
            profile.teamserver.port
        )
    })
}

#[instrument(skip(profile), fields(bind_host = %profile.teamserver.host))]
async fn build_tls_config(profile: &Profile) -> Result<RustlsConfig> {
    let subject_alt_names = tls_subject_alt_names(&profile.teamserver.host);
    let identity = resolve_tls_identity(&subject_alt_names, None, TlsKeyAlgorithm::EcdsaP256)
        .context("failed to resolve teamserver TLS identity")?;

    RustlsConfig::from_pem(identity.certificate_pem().to_vec(), identity.private_key_pem().to_vec())
        .await
        .context("failed to build rustls configuration")
}

fn tls_subject_alt_names(host: &str) -> Vec<String> {
    let mut names = vec![host.to_owned()];

    if host.parse::<IpAddr>().is_ok_and(|address| address.is_unspecified()) {
        names.push("127.0.0.1".to_owned());
        names.push("localhost".to_owned());
    }

    names
}

#[instrument(skip(handle))]
async fn wait_for_shutdown_signal(handle: Handle<SocketAddr>) {
    let signal = async {
        let ctrl_c = async {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {}
                Err(error) => tracing::error!(%error, "failed to listen for SIGINT"),
            }
        };

        #[cfg(unix)]
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(error) => tracing::error!(%error, "failed to listen for SIGTERM"),
            }
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {}
            _ = terminate => {}
        }
    };

    signal.await;
    info!(timeout_seconds = GRACEFUL_SHUTDOWN_TIMEOUT.as_secs(), "shutdown signal received");
    handle.graceful_shutdown(Some(GRACEFUL_SHUTDOWN_TIMEOUT));
}

#[instrument(skip(listeners, profile), fields(listener_count = profile_listener_names(profile).len()))]
async fn start_new_profile_listeners(
    listeners: &ListenerManager,
    profile: &Profile,
) -> Result<(), ListenerManagerError> {
    let profile_listener_names = profile_listener_names(profile);
    let summaries = listeners.list().await?;
    let new_profile_listener_names: Vec<String> = summaries
        .into_iter()
        .filter(|summary| {
            summary.state.status == red_cell::ListenerStatus::Created
                && profile_listener_names.iter().any(|name| name == &summary.name)
        })
        .map(|summary| summary.name)
        .collect();

    for listener in new_profile_listener_names {
        match listeners.start(listener.as_str()).await {
            Ok(_)
            | Err(ListenerManagerError::ListenerAlreadyRunning { .. })
            | Err(ListenerManagerError::StartFailed { .. }) => {}
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn profile_listener_names(profile: &Profile) -> Vec<String> {
    let mut names = Vec::new();
    names.extend(profile.listeners.http.iter().map(|listener| listener.name.clone()));
    names.extend(profile.listeners.smb.iter().map(|listener| listener.name.clone()));
    names.extend(profile.listeners.external.iter().map(|listener| listener.name.clone()));
    names.extend(profile.listeners.dns.iter().map(|listener| listener.name.clone()));
    names
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        Cli, load_profile, profile_listener_names, resolve_bind_addr, resolve_database_path,
        start_new_profile_listeners, tls_subject_alt_names,
    };
    use axum::extract::FromRef;
    use clap::Parser;
    use red_cell::{
        AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
        ListenerManager, ListenerStatus, LoginRateLimiter, OperatorConnectionManager,
        PayloadBuilderService, SocketRelayManager, TeamserverState,
    };
    use red_cell_common::config::{OperatorRole, Profile};
    use tempfile::NamedTempFile;

    #[test]
    fn cli_requires_profile_argument() {
        let result = Cli::try_parse_from(["red-cell"]);

        assert!(result.is_err());
    }

    #[test]
    fn cli_parses_profile_and_debug_flag() {
        let cli = Cli::try_parse_from(["red-cell", "--profile", "teamserver.yaotl", "--debug"])
            .expect("CLI arguments should parse");

        assert!(cli.debug);
        assert_eq!(cli.profile.to_string_lossy(), "teamserver.yaotl");
        assert!(cli.database.is_none());
    }

    #[test]
    fn database_path_defaults_to_profile_name() {
        let path = resolve_database_path(Path::new("/tmp/teamserver.yaotl"), None);

        assert_eq!(path, PathBuf::from("/tmp/teamserver.sqlite"));
    }

    #[test]
    fn tls_subject_alt_names_expand_unspecified_bind_hosts() {
        assert_eq!(
            tls_subject_alt_names("0.0.0.0"),
            vec!["0.0.0.0".to_owned(), "127.0.0.1".to_owned(), "localhost".to_owned()]
        );
    }

    #[tokio::test]
    async fn resolve_bind_addr_uses_profile_host_and_port() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let addr = resolve_bind_addr(&profile).await.expect("address should resolve");

        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_eq!(addr.port(), 40056);
    }

    #[test]
    fn load_profile_rejects_invalid_configuration() {
        let temp_file = NamedTempFile::new().expect("temporary file should be created");
        std::fs::write(
            temp_file.path(),
            r#"
            Teamserver {
              Host = ""
              Port = 0
            }

            Operators {}
            Demon {}
            "#,
        )
        .expect("invalid profile should be written");

        let error = load_profile(&temp_file.path().to_path_buf()).expect_err("load should fail");
        let message = error.to_string();

        assert!(message.contains("profile validation failed"));
        assert!(message.contains("Teamserver.Host"));
    }

    #[tokio::test]
    async fn app_state_exposes_shared_services_via_from_ref() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "Neo" {
                Password = "password1234"
                Role = "Operator"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");
        let database = Database::connect_in_memory().await.expect("database should initialize");
        let agent_registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
        let state = TeamserverState {
            auth: AuthService::from_profile(&profile),
            api: ApiRuntime::from_profile(&profile),
            database: database.clone(),
            events: events.clone(),
            connections: OperatorConnectionManager::new(),
            agent_registry: agent_registry.clone(),
            listeners: ListenerManager::new(
                database,
                agent_registry,
                events,
                sockets.clone(),
                None,
            ),
            payload_builder: PayloadBuilderService::disabled_for_tests(),
            sockets,
            webhooks: AuditWebhookNotifier::from_profile(&profile),
            profile,
            login_rate_limiter: LoginRateLimiter::new(),
        };

        let _ = AuthService::from_ref(&state);
        let _ = ApiRuntime::from_ref(&state);
        let _ = Database::from_ref(&state);
        let _ = EventBus::from_ref(&state);
        let _ = OperatorConnectionManager::from_ref(&state);
        let _ = AgentRegistry::from_ref(&state);
        let _ = SocketRelayManager::from_ref(&state);
        let _ = ListenerManager::from_ref(&state);
        let _ = PayloadBuilderService::from_ref(&state);
    }

    #[test]
    fn explicit_operator_roles_parse_in_teamserver_profiles() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "admin" {
                Password = "password1234"
              }
              user "operator" {
                Password = "password1234"
                Role = "Operator"
              }
              user "analyst" {
                Password = "password1234"
                Role = "Analyst"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        assert_eq!(profile.operators.users["admin"].role, OperatorRole::Admin);
        assert_eq!(profile.operators.users["operator"].role, OperatorRole::Operator);
        assert_eq!(profile.operators.users["analyst"].role, OperatorRole::Analyst);
    }

    #[test]
    fn profile_listener_names_collect_all_listener_types() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "operator" {
                Password = "password1234"
              }
            }

            Listeners {
              Http = [{
                Name = "http"
                Hosts = ["127.0.0.1"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 8443
                Secure = false
              }]
              Smb = [{
                Name = "smb"
                PipeName = "foo"
              }]
              External = [{
                Name = "ext"
                Endpoint = "svc"
              }]
              Dns = [{
                Name = "dns"
                HostBind = "127.0.0.1"
                PortBind = 5353
                Domain = "c2.example.com"
                RecordTypes = ["TXT"]
              }]
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        assert_eq!(profile_listener_names(&profile), vec!["http", "smb", "ext", "dns"]);
    }

    #[tokio::test]
    async fn startup_only_auto_starts_new_profile_listeners() {
        let port = available_port().expect("ephemeral port should be available");
        let profile = Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            Listeners {{
              Http = [{{
                Name = "http"
                Hosts = ["127.0.0.1"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = {port}
                Secure = false
              }}]
            }}

            Demon {{}}
            "#
        ))
        .expect("profile should parse");

        let database = Database::connect_in_memory().await.expect("database should initialize");
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let listeners = ListenerManager::new(database, registry, events, sockets, None);

        listeners.sync_profile(&profile).await.expect("profile listeners should sync");
        start_new_profile_listeners(&listeners, &profile)
            .await
            .expect("new profile listeners should auto-start");
        assert_eq!(
            listeners.summary("http").await.expect("listener should exist").state.status,
            ListenerStatus::Running
        );

        listeners.stop("http").await.expect("listener should stop cleanly");
        listeners.sync_profile(&profile).await.expect("profile listeners should re-sync");
        listeners.restore_running().await.expect("restore should succeed");
        start_new_profile_listeners(&listeners, &profile)
            .await
            .expect("startup should ignore explicitly stopped listeners");

        assert_eq!(
            listeners.summary("http").await.expect("listener should exist").state.status,
            ListenerStatus::Stopped
        );
    }

    #[tokio::test]
    async fn startup_restores_supported_listeners_when_external_restore_fails() {
        let port = available_port().expect("ephemeral port should be available");
        let profile = Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            Listeners {{
              Http = [{{
                Name = "http"
                Hosts = ["127.0.0.1"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = {port}
                Secure = false
              }}]
              External = [{{
                Name = "external"
                Endpoint = "svc"
              }}]
            }}

            Demon {{}}
            "#
        ))
        .expect("profile should parse");

        let database = Database::connect_in_memory().await.expect("database should initialize");
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let listeners = ListenerManager::new(database, registry, events, sockets, None);

        listeners.sync_profile(&profile).await.expect("profile listeners should sync");
        listeners
            .repository()
            .set_state("http", ListenerStatus::Running, None)
            .await
            .expect("http state should update");
        listeners
            .repository()
            .set_state("external", ListenerStatus::Running, None)
            .await
            .expect("external state should update");

        listeners.restore_running().await.expect("restore should continue");
        start_new_profile_listeners(&listeners, &profile)
            .await
            .expect("startup should continue after external restore failure");

        let http = listeners.summary("http").await.expect("http listener should exist");
        let external = listeners.summary("external").await.expect("external listener should exist");

        assert_eq!(http.state.status, ListenerStatus::Running);
        assert_eq!(external.state.status, ListenerStatus::Error);
        assert!(external.state.last_error.as_deref().is_some_and(|message| {
            message.contains("not implemented") && message.contains("svc")
        }));
    }

    #[tokio::test]
    async fn startup_marks_new_external_profile_listener_as_error_and_continues() {
        let port = available_port().expect("ephemeral port should be available");
        let profile = Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            Listeners {{
              Http = [{{
                Name = "http"
                Hosts = ["127.0.0.1"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = {port}
                Secure = false
              }}]
              External = [{{
                Name = "external"
                Endpoint = "svc"
              }}]
            }}

            Demon {{}}
            "#
        ))
        .expect("profile should parse");

        let database = Database::connect_in_memory().await.expect("database should initialize");
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let listeners = ListenerManager::new(database, registry, events, sockets, None);

        listeners.sync_profile(&profile).await.expect("profile listeners should sync");
        start_new_profile_listeners(&listeners, &profile)
            .await
            .expect("startup should continue when external listeners fail to start");

        let http = listeners.summary("http").await.expect("http listener should exist");
        let external = listeners.summary("external").await.expect("external listener should exist");

        assert_eq!(http.state.status, ListenerStatus::Running);
        assert_eq!(external.state.status, ListenerStatus::Error);
        assert!(external.state.last_error.as_deref().is_some_and(|message| {
            message.contains("not implemented") && message.contains("svc")
        }));
    }

    fn available_port() -> std::io::Result<u16> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        Ok(listener.local_addr()?.port())
    }
}
