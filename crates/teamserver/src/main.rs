use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    body::Body,
    extract::{FromRef, Path as AxumPath, State},
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::{any, get, post},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use clap::Parser;
use red_cell::{
    AuthService, Database, EventBus, ListenerManagementAccess, ListenerManager,
    ListenerManagerError, ListenerMarkRequest, ListenerSummary, OperatorConnectionManager,
    ReadAccess, websocket_routes,
};
use red_cell_common::ListenerConfig;
use red_cell_common::config::{Profile, ProfileValidationError};
use red_cell_common::tls::{
    TlsKeyAlgorithm, install_default_crypto_provider, resolve_tls_identity,
};
use tokio::net::lookup_host;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

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

#[derive(Debug, Clone)]
struct AppState {
    profile: Profile,
    database: Database,
    auth: AuthService,
    events: EventBus,
    connections: OperatorConnectionManager,
    listeners: ListenerManager,
}

impl FromRef<AppState> for AuthService {
    fn from_ref(input: &AppState) -> Self {
        input.auth.clone()
    }
}

impl FromRef<AppState> for Database {
    fn from_ref(input: &AppState) -> Self {
        input.database.clone()
    }
}

impl FromRef<AppState> for EventBus {
    fn from_ref(input: &AppState) -> Self {
        input.events.clone()
    }
}

impl FromRef<AppState> for OperatorConnectionManager {
    fn from_ref(input: &AppState) -> Self {
        input.connections.clone()
    }
}

impl FromRef<AppState> for ListenerManager {
    fn from_ref(input: &AppState) -> Self {
        input.listeners.clone()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.debug)?;

    let profile = load_profile(&cli.profile)
        .with_context(|| format!("failed to load profile from {}", cli.profile.display()))?;
    let database_path = resolve_database_path(&cli.profile, cli.database.as_ref());
    let database = Database::connect(&database_path)
        .await
        .with_context(|| format!("failed to open database {}", database_path.display()))?;
    let listeners = ListenerManager::new(database.clone());

    listeners.sync_profile(&profile).await?;
    listeners.restore_running().await?;
    start_profile_listeners(&listeners, &profile).await?;

    let bind_addr = resolve_bind_addr(&profile).await?;
    install_default_crypto_provider();
    let tls_config = build_tls_config(&profile).await?;
    let router = build_router(AppState {
        profile: profile.clone(),
        database,
        auth: AuthService::from_profile(&profile),
        events: EventBus::default(),
        connections: OperatorConnectionManager::new(),
        listeners,
    });
    let handle = Handle::new();

    tokio::spawn(wait_for_shutdown_signal(handle.clone()));

    info!("starting teamserver on https://{bind_addr}");

    axum_server::bind_rustls(bind_addr, tls_config)
        .handle(handle)
        .serve(router.into_make_service())
        .await
        .context("teamserver exited with an error")?;

    Ok(())
}

fn init_tracing(debug_logging: bool) -> Result<()> {
    let filter = if debug_logging {
        EnvFilter::try_new("debug")
    } else {
        EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))
    }
    .context("failed to configure tracing filter")?;

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .try_init()
        .map_err(|error| anyhow!("failed to initialize tracing subscriber: {error}"))
}

fn resolve_database_path(profile: &Path, configured: Option<&PathBuf>) -> PathBuf {
    configured.cloned().unwrap_or_else(|| {
        let mut path = profile.to_path_buf();
        path.set_extension("sqlite");
        path
    })
}

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

fn build_router(state: AppState) -> Router {
    Router::new()
        .nest("/havoc", websocket_routes())
        .nest("/api/v1", api_routes())
        .fallback(any(agent_listener_placeholder))
        .with_state(state)
}

fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(api_placeholder))
        .route("/listeners", get(list_listeners).post(create_listener))
        .route("/listeners/{name}", get(get_listener).put(update_listener).delete(delete_listener))
        .route("/listeners/{name}/start", post(start_listener))
        .route("/listeners/{name}/stop", post(stop_listener))
        .route("/listeners/{name}/mark", post(mark_listener))
}

async fn api_placeholder(State(state): State<AppState>, operator: ReadAccess) -> impl IntoResponse {
    debug!(
        username = %operator.username,
        role = ?operator.role,
        listener_count = state.profile.listeners.http.len()
            + state.profile.listeners.smb.len()
            + state.profile.listeners.external.len(),
        "rest api placeholder hit"
    );

    (StatusCode::NOT_IMPLEMENTED, "rest api endpoint not implemented yet")
}

async fn list_listeners(
    State(state): State<AppState>,
    _operator: ReadAccess,
) -> Result<Json<Vec<ListenerSummary>>, ListenerManagerError> {
    Ok(Json(state.listeners.list().await?))
}

async fn get_listener(
    State(state): State<AppState>,
    _operator: ReadAccess,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    Ok(Json(state.listeners.summary(&name).await?))
}

async fn create_listener(
    State(state): State<AppState>,
    _operator: ListenerManagementAccess,
    Json(config): Json<ListenerConfig>,
) -> Result<(StatusCode, Json<ListenerSummary>), ListenerManagerError> {
    let summary = state.listeners.create(config).await?;
    Ok((StatusCode::CREATED, Json(summary)))
}

async fn update_listener(
    State(state): State<AppState>,
    _operator: ListenerManagementAccess,
    AxumPath(name): AxumPath<String>,
    Json(config): Json<ListenerConfig>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    if config.name() != name {
        return Err(ListenerManagerError::InvalidConfig {
            message: "path name must match listener configuration name".to_owned(),
        });
    }

    Ok(Json(state.listeners.update(config).await?))
}

async fn delete_listener(
    State(state): State<AppState>,
    _operator: ListenerManagementAccess,
    AxumPath(name): AxumPath<String>,
) -> Result<StatusCode, ListenerManagerError> {
    state.listeners.delete(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn start_listener(
    State(state): State<AppState>,
    _operator: ListenerManagementAccess,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    Ok(Json(state.listeners.start(&name).await?))
}

async fn stop_listener(
    State(state): State<AppState>,
    _operator: ListenerManagementAccess,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    Ok(Json(state.listeners.stop(&name).await?))
}

async fn mark_listener(
    State(state): State<AppState>,
    _operator: ListenerManagementAccess,
    AxumPath(name): AxumPath<String>,
    Json(request): Json<ListenerMarkRequest>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    let summary = match request.mark.as_str() {
        mark if mark.eq_ignore_ascii_case("start") || mark.eq_ignore_ascii_case("online") => {
            state.listeners.start(&name).await?
        }
        mark if mark.eq_ignore_ascii_case("stop") || mark.eq_ignore_ascii_case("offline") => {
            state.listeners.stop(&name).await?
        }
        _ => {
            return Err(ListenerManagerError::UnsupportedMark { mark: request.mark });
        }
    };

    Ok(Json(summary))
}

async fn agent_listener_placeholder(
    State(state): State<AppState>,
    request: Request<Body>,
) -> impl IntoResponse {
    debug!(
        method = %request.method(),
        path = %request.uri().path(),
        secure_listener_count = state
            .profile
            .listeners
            .http
            .iter()
            .filter(|listener| listener.secure)
            .count(),
        "agent listener placeholder hit"
    );

    (StatusCode::NOT_IMPLEMENTED, "agent listener endpoint not implemented yet")
}

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

async fn start_profile_listeners(
    listeners: &ListenerManager,
    profile: &Profile,
) -> Result<(), ListenerManagerError> {
    for listener in profile_listener_names(profile) {
        match listeners.start(listener.as_str()).await {
            Ok(_) | Err(ListenerManagerError::ListenerAlreadyRunning { .. }) => {}
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
    names
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        AppState, Cli, load_profile, profile_listener_names, resolve_bind_addr,
        resolve_database_path, tls_subject_alt_names,
    };
    use axum::extract::FromRef;
    use clap::Parser;
    use red_cell::{AuthService, Database, EventBus, ListenerManager, OperatorConnectionManager};
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
        let state = AppState {
            auth: AuthService::from_profile(&profile),
            database: database.clone(),
            events: EventBus::default(),
            connections: OperatorConnectionManager::new(),
            listeners: ListenerManager::new(database),
            profile,
        };

        let _ = AuthService::from_ref(&state);
        let _ = Database::from_ref(&state);
        let _ = ListenerManager::from_ref(&state);
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
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        assert_eq!(profile_listener_names(&profile), vec!["http", "smb", "ext"]);
    }
}
