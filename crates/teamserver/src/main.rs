use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    body::Body,
    extract::{
        FromRef, State,
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    },
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::{any, get},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use clap::Parser;
use red_cell::{
    AuthError, AuthService, AuthenticationFailure, AuthenticationResult, ReadAccess,
    authorize_websocket_command, login_failure_message, login_success_message,
};
use red_cell_common::config::{Profile, ProfileValidationError};
use red_cell_common::operator::OperatorMessage;
use red_cell_common::tls::{TlsKeyAlgorithm, resolve_tls_identity};
use tokio::net::lookup_host;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Parser)]
#[command(name = "red-cell", about = "Red Cell teamserver")]
struct Cli {
    /// Path to the Havoc-compatible YAOTL profile.
    #[arg(long)]
    profile: PathBuf,
    /// Enable debug-level logging.
    #[arg(long, default_value_t = false)]
    debug: bool,
}

#[derive(Debug, Clone)]
struct AppState {
    profile: Profile,
    auth: AuthService,
}

impl FromRef<AppState> for AuthService {
    fn from_ref(input: &AppState) -> Self {
        input.auth.clone()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.debug)?;

    let profile = load_profile(&cli.profile)
        .with_context(|| format!("failed to load profile from {}", cli.profile.display()))?;
    let bind_addr = resolve_bind_addr(&profile).await?;
    let tls_config = build_tls_config(&profile).await?;
    let router = build_router(profile.clone());
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

fn build_router(profile: Profile) -> Router {
    let auth = AuthService::from_profile(&profile);

    Router::new()
        .nest("/havoc", websocket_routes())
        .nest("/api/v1", api_routes())
        .fallback(any(agent_listener_placeholder))
        .with_state(AppState { profile, auth })
}

fn websocket_routes() -> Router<AppState> {
    Router::new().route("/", get(websocket_handler))
}

fn api_routes() -> Router<AppState> {
    Router::new().route("/", get(api_placeholder))
}

async fn websocket_handler(
    State(state): State<AppState>,
    websocket: WebSocketUpgrade,
) -> impl IntoResponse {
    debug!(
        operator_count = state.profile.operators.users.len(),
        "operator websocket upgrade requested"
    );

    websocket.on_upgrade(move |socket| handle_operator_socket(state, socket))
}

async fn handle_operator_socket(state: AppState, mut socket: WebSocket) {
    let connection_id = Uuid::new_v4();

    let Some(frame) = socket.recv().await else {
        warn!(%connection_id, "operator websocket closed before authentication");
        return;
    };

    let response = match frame {
        Ok(WsMessage::Text(payload)) => {
            authenticate_operator_message(&state.auth, connection_id, payload.as_str()).await
        }
        Ok(WsMessage::Close(_)) => return,
        Ok(_) => {
            send_login_error(
                &mut socket,
                "",
                AuthenticationFailure::WrongPassword,
                "operator websocket requires a text login message",
            )
            .await;
            let _ = socket.send(WsMessage::Close(None)).await;
            return;
        }
        Err(error) => {
            warn!(%connection_id, %error, "failed to receive operator authentication frame");
            return;
        }
    };

    if send_operator_message(&mut socket, &response).await.is_err() {
        let _ = state.auth.remove_connection(connection_id).await;
        return;
    }

    match state.auth.session_for_connection(connection_id).await {
        Some(session) => {
            info!(
                %connection_id,
                username = %session.username,
                token = %session.token,
                "operator authenticated"
            );
        }
        None => {
            let _ = socket.send(WsMessage::Close(None)).await;
            return;
        }
    }

    let Some(session) = state.auth.session_for_connection(connection_id).await else {
        let _ = socket.send(WsMessage::Close(None)).await;
        return;
    };

    while let Some(frame) = socket.recv().await {
        match frame {
            Ok(WsMessage::Close(_)) => break,
            Ok(WsMessage::Text(payload)) => {
                match serde_json::from_str::<OperatorMessage>(payload.as_str()) {
                    Ok(message) => match authorize_websocket_command(&session, &message) {
                        Ok(permission) => {
                            debug!(
                                %connection_id,
                                username = %session.username,
                                role = ?session.role,
                                permission = permission.as_str(),
                                "authorized operator websocket command placeholder"
                            );
                        }
                        Err(error) => {
                            warn!(
                                %connection_id,
                                username = %session.username,
                                role = ?session.role,
                                %error,
                                "rejecting unauthorized operator websocket command"
                            );
                            let _ = socket.send(WsMessage::Close(None)).await;
                            break;
                        }
                    },
                    Err(error) => {
                        warn!(%connection_id, %error, "failed to parse operator websocket message");
                        let _ = socket.send(WsMessage::Close(None)).await;
                        break;
                    }
                }
            }
            Ok(_) => {}
            Err(error) => {
                warn!(%connection_id, %error, "operator websocket receive loop failed");
                break;
            }
        }
    }

    let _ = state.auth.remove_connection(connection_id).await;
}

async fn authenticate_operator_message(
    auth: &AuthService,
    connection_id: Uuid,
    payload: &str,
) -> red_cell_common::operator::OperatorMessage {
    match auth.authenticate_message(connection_id, payload).await {
        Ok(AuthenticationResult::Success(success)) => {
            login_success_message(&success.username, &success.token)
        }
        Ok(AuthenticationResult::Failure(failure)) => login_failure_message("", &failure),
        Err(AuthError::InvalidLoginMessage) => {
            login_failure_message("", &AuthenticationFailure::WrongPassword)
        }
        Err(AuthError::InvalidMessageJson(error)) => {
            warn!(%connection_id, %error, "failed to parse operator login message");
            login_failure_message("", &AuthenticationFailure::WrongPassword)
        }
    }
}

async fn send_operator_message(
    socket: &mut WebSocket,
    message: &red_cell_common::operator::OperatorMessage,
) -> Result<()> {
    let payload = serde_json::to_string(message).context("failed to serialize operator message")?;
    socket
        .send(WsMessage::Text(payload.into()))
        .await
        .context("failed to send operator websocket message")?;
    Ok(())
}

async fn send_login_error(
    socket: &mut WebSocket,
    user: &str,
    failure: AuthenticationFailure,
    log_message: &str,
) {
    warn!(%log_message, "rejecting operator websocket authentication");

    if let Err(error) = send_operator_message(socket, &login_failure_message(user, &failure)).await
    {
        warn!(%error, "failed to send operator websocket authentication error");
    }
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

#[cfg(test)]
mod tests {
    use super::{AppState, Cli, load_profile, resolve_bind_addr, tls_subject_alt_names};
    use axum::extract::FromRef;
    use clap::Parser;
    use red_cell::AuthService;
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

    #[test]
    fn app_state_exposes_auth_service_via_from_ref() {
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

        let state = AppState { auth: AuthService::from_profile(&profile), profile };
        let _ = AuthService::from_ref(&state);
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
}
