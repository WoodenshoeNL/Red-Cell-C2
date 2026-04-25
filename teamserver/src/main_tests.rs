use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{
    Cli, build_tls_config, first_resolved_addr, load_or_create_master_key, load_profile,
    profile_listener_names, resolve_bind_addr, resolve_database_path, run_shutdown_sequence,
    start_new_profile_listeners, tls_subject_alt_names,
};
use axum::extract::FromRef;
use axum_server::Handle;
use clap::Parser;
use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, ListenerManagerError, ListenerStatus, LoginRateLimiter,
    OperatorConnectionManager, PayloadBuilderService, ShutdownController, SocketRelayManager,
    TeamserverState,
};
use red_cell_common::ListenerProtocol;
use red_cell_common::config::{OperatorRole, Profile};
use red_cell_common::tls::{TlsKeyAlgorithm, generate_self_signed_tls_identity};
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
fn database_path_uses_explicit_override() {
    let path = resolve_database_path(
        Path::new("/tmp/teamserver.yaotl"),
        Some(&PathBuf::from("/data/custom.db")),
    );

    assert_eq!(path, PathBuf::from("/data/custom.db"));
}

#[test]
fn tls_subject_alt_names_expand_ipv4_unspecified() {
    assert_eq!(
        tls_subject_alt_names("0.0.0.0"),
        vec!["0.0.0.0".to_owned(), "127.0.0.1".to_owned(), "localhost".to_owned()]
    );
}

#[test]
fn tls_subject_alt_names_expand_ipv6_unspecified() {
    assert_eq!(
        tls_subject_alt_names("::"),
        vec!["::".to_owned(), "127.0.0.1".to_owned(), "localhost".to_owned()]
    );
}

#[test]
fn tls_subject_alt_names_specific_ipv4_returns_only_itself() {
    assert_eq!(tls_subject_alt_names("127.0.0.1"), vec!["127.0.0.1".to_owned()]);
}

#[test]
fn tls_subject_alt_names_hostname_returns_only_itself() {
    assert_eq!(tls_subject_alt_names("example.com"), vec!["example.com".to_owned()]);
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
fn first_resolved_addr_returns_error_when_iterator_is_empty() {
    let empty = std::iter::empty::<SocketAddr>();

    let error = first_resolved_addr(empty, "ghost.example.com", 443)
        .expect_err("should fail for empty iterator");

    let message = error.to_string();
    assert!(
        message.contains("no socket addresses resolved"),
        "error should mention 'no socket addresses resolved', got: {message}"
    );
    assert!(message.contains("ghost.example.com"), "error should mention the host, got: {message}");
    assert!(message.contains("443"), "error should mention the port, got: {message}");
}

#[test]
fn first_resolved_addr_returns_first_address_from_iterator() {
    let addr1: SocketAddr = "127.0.0.1:8080".parse().expect("valid socket addr");
    let addr2: SocketAddr = "[::1]:8080".parse().expect("valid socket addr");
    let addrs = vec![addr1, addr2];

    let result = first_resolved_addr(addrs.into_iter(), "localhost", 8080).expect("should succeed");

    assert_eq!(result, addr1);
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
fn load_profile_accepts_service_block_configuration() {
    let temp_file = NamedTempFile::new().expect("temporary file should be created");
    std::fs::write(
        temp_file.path(),
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

        Service {
          Endpoint = "service-endpoint"
          Password = "service-password"
        }

        Demon {}
        "#,
    )
    .expect("profile should be written");

    let profile = load_profile(&temp_file.path().to_path_buf())
        .expect("profile with Service block should load successfully");
    assert!(profile.service.is_some());
}

#[test]
fn load_profile_accepts_external_listener_configuration() {
    let temp_file = NamedTempFile::new().expect("temporary file should be created");
    std::fs::write(
        temp_file.path(),
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

        Listeners {
          External {
            Name = "bridge"
            Endpoint = "/svc"
          }
        }

        Demon {}
        "#,
    )
    .expect("profile should be written");

    let profile = load_profile(&temp_file.path().to_path_buf())
        .expect("profile with External listener should load successfully");
    assert_eq!(profile.listeners.external.len(), 1);
    assert_eq!(profile.listeners.external[0].name, "bridge");
    assert_eq!(profile.listeners.external[0].endpoint, "/svc");
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
        auth: AuthService::from_profile(&profile).expect("auth service should initialize"),
        api: ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
        database: database.clone(),
        events: events.clone(),
        connections: OperatorConnectionManager::new(),
        agent_registry: agent_registry.clone(),
        listeners: ListenerManager::new(database, agent_registry, events, sockets.clone(), None),
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets,
        webhooks: AuditWebhookNotifier::from_profile(&profile),
        profile,
        profile_path: "test.yaotl".to_owned(),
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: red_cell::ShutdownController::new(),
        service_bridge: None,
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: red_cell::metrics::standalone_metrics_handle(),
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
          Dns = [{
            Name = "dns"
            HostBind = "127.0.0.1"
            PortBind = 5353
            Domain = "c2.example.com"
            RecordTypes = ["TXT"]
          }]
          External = [{
            Name = "bridge"
            Endpoint = "/svc"
          }]
        }

        Demon {}
        "#,
    )
    .expect("profile should parse");

    assert_eq!(profile_listener_names(&profile), vec!["http", "smb", "dns", "bridge"]);
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
async fn startup_auto_starts_new_smb_profile_listener() {
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
          Smb = [{
            Name = "smb-pipe"
            PipeName = "test-pipe"
          }]
        }

        Demon {}
        "#,
    )
    .expect("profile should parse");

    let database = Database::connect_in_memory().await.expect("database should initialize");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let listeners = ListenerManager::new(database, registry, events, sockets, None);

    listeners.sync_profile(&profile).await.expect("profile listeners should sync");
    start_new_profile_listeners(&listeners, &profile)
        .await
        .expect("new SMB profile listener should auto-start");

    let smb = listeners.summary("smb-pipe").await.expect("SMB listener should exist");
    assert_eq!(
        smb.state.status,
        ListenerStatus::Running,
        "SMB listener should transition to Running during startup"
    );
}

#[tokio::test]
async fn startup_auto_starts_new_dns_profile_listener() {
    let port = available_udp_port().expect("ephemeral UDP port should be available");
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
          Dns = [{{
            Name = "dns-c2"
            HostBind = "127.0.0.1"
            PortBind = {port}
            Domain = "c2.example.com"
            RecordTypes = ["TXT"]
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
        .expect("new DNS profile listener should auto-start");

    let dns = listeners.summary("dns-c2").await.expect("DNS listener should exist");
    assert_eq!(
        dns.state.status,
        ListenerStatus::Running,
        "DNS listener should transition to Running during startup"
    );
}

#[tokio::test]
async fn startup_removes_profile_listener_deleted_before_next_boot() {
    let old_port = available_port().expect("ephemeral port should be available");
    let old_profile = Profile::parse(&format!(
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
            Name = "old-http"
            Hosts = ["127.0.0.1"]
            HostBind = "127.0.0.1"
            HostRotation = "round-robin"
            PortBind = {old_port}
            Secure = false
          }}]
        }}

        Demon {{}}
        "#
    ))
    .expect("old profile should parse");
    let new_profile = Profile::parse(
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

        Demon {}
        "#,
    )
    .expect("new profile should parse");

    let database = Database::connect_in_memory().await.expect("database should initialize");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let listeners = ListenerManager::new(database, registry, events, sockets, None);

    listeners.sync_profile(&old_profile).await.expect("old profile listeners should sync");
    listeners
        .repository()
        .set_state("old-http", ListenerStatus::Running, None)
        .await
        .expect("old listener state should update");

    listeners.sync_profile(&new_profile).await.expect("new profile listeners should sync");
    listeners.restore_running().await.expect("restore should succeed");
    start_new_profile_listeners(&listeners, &new_profile)
        .await
        .expect("startup should ignore deleted profile listeners");

    assert!(matches!(
        listeners.summary("old-http").await,
        Err(ListenerManagerError::ListenerNotFound { .. })
    ));
    assert!(listeners.list().await.expect("listeners should list").is_empty());
}

#[tokio::test]
async fn startup_restores_supported_listeners_without_external_special_cases() {
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
    listeners
        .repository()
        .set_state("http", ListenerStatus::Running, None)
        .await
        .expect("http state should update");

    listeners.restore_running().await.expect("restore should continue");
    start_new_profile_listeners(&listeners, &profile)
        .await
        .expect("startup should continue for supported listeners");

    let http = listeners.summary("http").await.expect("http listener should exist");

    assert_eq!(http.state.status, ListenerStatus::Running);
}

#[tokio::test]
async fn sync_profile_persists_external_listener_configs() {
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
          External = [{
            Name = "external"
            Endpoint = "/svc"
          }]
        }

        Demon {}
        "#,
    )
    .expect("profile should parse");

    let database = Database::connect_in_memory().await.expect("database should initialize");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let listeners = ListenerManager::new(database, registry, events, sockets, None);

    listeners
        .sync_profile(&profile)
        .await
        .expect("sync_profile must succeed with External entries");

    let summary =
        listeners.summary("external").await.expect("External listener should have been persisted");
    assert_eq!(summary.config.protocol(), ListenerProtocol::External);
}

#[tokio::test]
async fn startup_fails_when_new_http_profile_listener_cannot_bind() {
    let occupied_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port should bind");
    let port =
        occupied_listener.local_addr().expect("occupied listener should have local address").port();
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
    let error = start_new_profile_listeners(&listeners, &profile)
        .await
        .expect_err("startup should fail when a new http listener cannot bind");

    assert!(matches!(error, ListenerManagerError::StartFailed { .. }));
    let http = listeners.summary("http").await.expect("http listener should exist");
    assert_eq!(http.state.status, ListenerStatus::Error);
    assert!(
        http.state.last_error.as_deref().is_some_and(|message| {
            message.contains("failed to bind") && message.to_lowercase().contains("already in use")
        }),
        "expected bind error, got {:?}",
        http.state.last_error
    );
}

#[tokio::test]
async fn startup_fails_when_restored_http_listener_cannot_bind() {
    let occupied_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port should bind");
    let port =
        occupied_listener.local_addr().expect("occupied listener should have local address").port();
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
    listeners
        .repository()
        .set_state("http", ListenerStatus::Running, None)
        .await
        .expect("http state should update");

    let error = listeners
        .restore_running()
        .await
        .expect_err("startup should fail when a restored http listener cannot bind");

    assert!(matches!(error, ListenerManagerError::StartFailed { .. }));
    let http = listeners.summary("http").await.expect("http listener should exist");
    assert_eq!(http.state.status, ListenerStatus::Error);
    assert!(
        http.state.last_error.as_deref().is_some_and(|message| {
            message.contains("failed to bind") && message.to_lowercase().contains("already in use")
        }),
        "expected bind error, got {:?}",
        http.state.last_error
    );
}

fn available_port() -> std::io::Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn available_udp_port() -> std::io::Result<u16> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    Ok(socket.local_addr()?.port())
}

#[tokio::test]
async fn build_tls_config_generates_and_persists_self_signed_cert_when_no_cert_configured() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let profile_path = temp_dir.path().join("teamserver.yaotl");
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

    red_cell_common::tls::install_default_crypto_provider();
    let _config = build_tls_config(&profile, &profile_path)
        .await
        .expect("build_tls_config should succeed with no cert configured");

    let cert_path = profile_path.with_extension("tls.crt");
    let key_path = profile_path.with_extension("tls.key");
    assert!(cert_path.exists(), "generated certificate should be persisted to disk");
    assert!(key_path.exists(), "generated private key should be persisted to disk");
}

#[tokio::test]
async fn build_tls_config_reloads_persisted_cert_on_subsequent_calls() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let profile_path = temp_dir.path().join("teamserver.yaotl");
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

    red_cell_common::tls::install_default_crypto_provider();
    let _first =
        build_tls_config(&profile, &profile_path).await.expect("first call should succeed");

    let cert_path = profile_path.with_extension("tls.crt");
    let cert_material_after_first = std::fs::read(&cert_path).expect("cert should exist");

    let _second =
        build_tls_config(&profile, &profile_path).await.expect("second call should succeed");

    let cert_material_after_second = std::fs::read(&cert_path).expect("cert should still exist");
    assert_eq!(
        cert_material_after_first, cert_material_after_second,
        "cert material must be stable across restarts when no explicit cert is configured"
    );
}

#[tokio::test]
async fn build_tls_config_advertises_http11_only_alpn() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let profile_path = temp_dir.path().join("teamserver.yaotl");
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

    red_cell_common::tls::install_default_crypto_provider();
    let config =
        build_tls_config(&profile, &profile_path).await.expect("build_tls_config should succeed");

    let server_config = config.get_inner();
    assert_eq!(
        server_config.alpn_protocols,
        vec![b"http/1.1".to_vec()],
        "ALPN must advertise only http/1.1 — h2 would break WebSocket upgrades"
    );
}

#[tokio::test]
async fn build_tls_config_uses_configured_cert_paths_from_profile() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let profile_path = temp_dir.path().join("teamserver.yaotl");

    // Write a pre-existing cert/key that should be used.
    let configured_identity =
        generate_self_signed_tls_identity(&["127.0.0.1".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");
    let configured_cert = temp_dir.path().join("custom.crt");
    let configured_key = temp_dir.path().join("custom.key");
    std::fs::write(&configured_cert, configured_identity.certificate_pem())
        .expect("cert should be written");
    std::fs::write(&configured_key, configured_identity.private_key_pem())
        .expect("key should be written");

    let profile = Profile::parse(&format!(
        r#"
        Teamserver {{
          Host = "127.0.0.1"
          Port = 40056
          Cert {{
            Cert = "{cert}"
            Key = "{key}"
          }}
        }}

        Operators {{
          user "Neo" {{
            Password = "password1234"
          }}
        }}

        Demon {{}}
        "#,
        cert = configured_cert.display(),
        key = configured_key.display(),
    ))
    .expect("profile with cert block should parse");

    red_cell_common::tls::install_default_crypto_provider();
    let _config = build_tls_config(&profile, &profile_path)
        .await
        .expect("build_tls_config should succeed with configured cert paths");

    // The auto-persist paths must not be created when explicit cert is configured.
    let auto_cert_path = profile_path.with_extension("tls.crt");
    assert!(
        !auto_cert_path.exists(),
        "auto-persist cert should not be written when explicit cert is configured"
    );
}

/// Build a minimal [`TeamserverState`] backed by an in-memory database for
/// shutdown orchestration tests.
async fn build_shutdown_test_state() -> (TeamserverState, ShutdownController) {
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

        Demon {}
        "#,
    )
    .expect("profile should parse");

    let database = Database::connect_in_memory().await.expect("database should initialize");
    let agent_registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
    let listeners = ListenerManager::new(
        database.clone(),
        agent_registry.clone(),
        events.clone(),
        sockets.clone(),
        None,
    );
    let shutdown = listeners.shutdown_controller();

    let state = TeamserverState {
        auth: AuthService::from_profile(&profile).expect("auth service should initialize"),
        api: ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
        database,
        events,
        connections: OperatorConnectionManager::new(),
        agent_registry,
        listeners,
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets,
        webhooks: AuditWebhookNotifier::from_profile(&profile),
        profile,
        profile_path: "test.yaotl".to_owned(),
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: shutdown.clone(),
        service_bridge: None,
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: red_cell::metrics::standalone_metrics_handle(),
    };

    (state, shutdown)
}

#[tokio::test]
async fn shutdown_sequence_closes_database() {
    let (state, shutdown) = build_shutdown_test_state().await;
    let pool = state.database.pool().clone();
    let handle: Handle<SocketAddr> = Handle::new();

    run_shutdown_sequence(handle, shutdown, state, Duration::from_secs(5))
        .await
        .expect("shutdown sequence should succeed");

    assert!(pool.is_closed(), "database pool should be closed after shutdown");
}

#[tokio::test]
async fn shutdown_sequence_initiates_shutdown_controller() {
    let (state, shutdown) = build_shutdown_test_state().await;
    let handle: Handle<SocketAddr> = Handle::new();

    assert!(!shutdown.is_shutting_down(), "shutdown should not be active before sequence");

    run_shutdown_sequence(handle, shutdown.clone(), state, Duration::from_secs(5))
        .await
        .expect("shutdown sequence should succeed");

    assert!(
        shutdown.is_shutting_down(),
        "shutdown controller should be in shutdown state after sequence"
    );
}

#[tokio::test]
async fn shutdown_sequence_completes_with_no_active_listeners() {
    let (state, shutdown) = build_shutdown_test_state().await;
    let pool = state.database.pool().clone();
    let handle: Handle<SocketAddr> = Handle::new();

    // With no active listeners or webhooks, shutdown should complete quickly
    // without hitting the timeout path.
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        run_shutdown_sequence(handle, shutdown.clone(), state, Duration::from_secs(5)),
    )
    .await
    .expect("shutdown should complete within timeout");

    result.expect("shutdown sequence should succeed");
    assert!(shutdown.is_shutting_down());
    assert!(pool.is_closed());
}

#[tokio::test]
async fn shutdown_sequence_warns_when_listener_drain_times_out() {
    let (state, shutdown) = build_shutdown_test_state().await;
    let pool = state.database.pool().clone();
    let handle: Handle<SocketAddr> = Handle::new();

    // Hold a callback guard so the listener drain cannot complete.
    let _stuck_callback =
        shutdown.try_track_callback().expect("callback tracking should succeed before shutdown");

    // Use a tiny timeout so the listener drain times out immediately,
    // exercising the `!drained` warning branch.
    run_shutdown_sequence(handle, shutdown.clone(), state, Duration::from_millis(1))
        .await
        .expect("shutdown sequence should succeed even when listener drain times out");

    assert!(shutdown.is_shutting_down());
    assert!(pool.is_closed(), "database should be closed even after listener timeout");
}

#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn shutdown_sequence_warns_when_webhook_drain_times_out() {
    let (state, shutdown) = build_shutdown_test_state().await;
    let pool = state.database.pool().clone();
    let handle: Handle<SocketAddr> = Handle::new();

    // Simulate a pending webhook delivery that will never complete.
    let _stuck_delivery = state.webhooks.simulate_stuck_delivery();

    // Use a tiny timeout so the webhook drain times out immediately,
    // exercising the `!state.webhooks.shutdown(timeout)` warning branch.
    run_shutdown_sequence(handle, shutdown.clone(), state, Duration::from_millis(1))
        .await
        .expect("shutdown sequence should succeed even when webhook drain times out");

    assert!(shutdown.is_shutting_down());
    assert!(pool.is_closed(), "database should be closed even after webhook timeout");
}

#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn shutdown_sequence_warns_when_both_listener_and_webhook_drain_time_out() {
    let (state, shutdown) = build_shutdown_test_state().await;
    let pool = state.database.pool().clone();
    let handle: Handle<SocketAddr> = Handle::new();

    // Hold both a callback guard and a stuck webhook delivery.
    let _stuck_callback =
        shutdown.try_track_callback().expect("callback tracking should succeed before shutdown");
    let _stuck_delivery = state.webhooks.simulate_stuck_delivery();

    run_shutdown_sequence(handle, shutdown.clone(), state, Duration::from_millis(1))
        .await
        .expect("shutdown sequence should succeed even when both drains time out");

    assert!(shutdown.is_shutting_down());
    assert!(pool.is_closed(), "database should be closed even after both timeouts");
}

#[tokio::test]
async fn shutdown_sequence_drains_active_listener_before_closing_database() {
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
            Name = "http-shutdown-test"
            Hosts = ["127.0.0.1"]
            HostBind = "127.0.0.1"
            HostRotation = "round-robin"
            PortBind = {port}
            Secure = false
          }}]
        }}

        Demon {{}}
        "#,
    ))
    .expect("profile should parse");

    let database = Database::connect_in_memory().await.expect("database should initialize");
    let agent_registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
    let listeners = ListenerManager::new(
        database.clone(),
        agent_registry.clone(),
        events.clone(),
        sockets.clone(),
        None,
    );
    let shutdown = listeners.shutdown_controller();

    listeners.sync_profile(&profile).await.expect("profile should sync");
    listeners.start("http-shutdown-test").await.expect("listener should start");

    let pool = database.pool().clone();
    let handle: Handle<SocketAddr> = Handle::new();
    let state = TeamserverState {
        auth: AuthService::from_profile(&profile).expect("auth service should initialize"),
        api: ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
        database,
        events,
        connections: OperatorConnectionManager::new(),
        agent_registry,
        listeners,
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets,
        webhooks: AuditWebhookNotifier::from_profile(&profile),
        profile,
        profile_path: "test.yaotl".to_owned(),
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: shutdown.clone(),
        service_bridge: None,
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: red_cell::metrics::standalone_metrics_handle(),
    };

    run_shutdown_sequence(handle, shutdown.clone(), state, Duration::from_secs(5))
        .await
        .expect("shutdown sequence should succeed with active listener");

    assert!(shutdown.is_shutting_down());
    assert!(pool.is_closed(), "database should be closed even with an active listener");
}

/// Regression test: an in-flight External-listener request that has acquired
/// a callback guard (as the teamserver fallback handler now does) must delay
/// database closure during `run_shutdown_sequence`, just like HTTP/SMB/DNS
/// callbacks do.
#[tokio::test]
async fn shutdown_sequence_waits_for_external_listener_callback_guard() {
    let (state, shutdown) = build_shutdown_test_state().await;

    // Create and start an External listener so we can grab its state.
    use red_cell_common::{ExternalListenerConfig, ListenerConfig};
    let ext_config = ListenerConfig::from(ExternalListenerConfig {
        name: "ext-drain-test".to_owned(),
        endpoint: "/drain-test".to_owned(),
    });
    state.listeners.create(ext_config).await.expect("create");
    state.listeners.start("ext-drain-test").await.expect("start");

    let ext_state = state
        .listeners
        .external_state_for_path("/drain-test")
        .await
        .expect("endpoint should be registered");

    // Simulate what the teamserver fallback handler does: acquire a callback
    // guard via ExternalListenerState::try_track_callback() *before* body
    // collection.  This guard must keep the callback drain open.
    let guard = ext_state.try_track_callback().expect("guard must succeed before shutdown");

    let pool = state.database.pool().clone();
    let handle: Handle<SocketAddr> = Handle::new();

    // Launch shutdown in the background with a generous timeout.
    let shutdown_handle = tokio::spawn({
        let shutdown = shutdown.clone();
        async move { run_shutdown_sequence(handle, shutdown, state, Duration::from_secs(5)).await }
    });

    // Give the shutdown sequence a moment to initiate and start draining.
    tokio::time::sleep(Duration::from_millis(20)).await;

    assert!(shutdown.is_shutting_down(), "shutdown should have been initiated");
    assert!(!pool.is_closed(), "database must NOT be closed while external callback guard is held");

    // Release the guard — this should allow the drain to complete and the
    // database to close.
    drop(guard);

    shutdown_handle
        .await
        .expect("shutdown task should not panic")
        .expect("shutdown sequence should succeed");

    assert!(pool.is_closed(), "database should be closed after external callback guard is dropped");
}

#[test]
fn master_key_rejects_oversized_file() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.sqlite");

    // Create a key file with 33 bytes (32 valid + 1 trailing)
    let key_path = dir.path().join("test.sqlite.key");
    let data = vec![0xABu8; 33];
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .unwrap();
        std::io::Write::write_all(&mut f, &data).unwrap();
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&key_path, &data).unwrap();
    }

    let err = load_or_create_master_key(&db_path).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("more than 32 bytes"), "expected trailing-byte error, got: {msg}",);
}

#[test]
fn master_key_accepts_exact_32_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.sqlite");
    let key_path = dir.path().join("test.sqlite.key");

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .unwrap();
        std::io::Write::write_all(&mut f, &[0xCDu8; 32]).unwrap();
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&key_path, &[0xCDu8; 32]).unwrap();
    }

    let key = load_or_create_master_key(&db_path).expect("exact 32-byte file should succeed");
    assert_eq!(key.as_bytes(), &[0xCDu8; 32]);
}

#[cfg(unix)]
#[test]
fn master_key_rejects_loose_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.sqlite");
    let key_path = dir.path().join("test.sqlite.key");

    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&key_path)
            .unwrap();
        std::io::Write::write_all(&mut f, &[0xABu8; 32]).unwrap();
    }

    let err = load_or_create_master_key(&db_path).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("mode") && msg.contains("0600"), "expected permission error, got: {msg}",);
}

#[cfg(unix)]
#[test]
fn master_key_rejects_world_readable_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.sqlite");
    let key_path = dir.path().join("test.sqlite.key");

    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o604)
            .open(&key_path)
            .unwrap();
        std::io::Write::write_all(&mut f, &[0xABu8; 32]).unwrap();
    }

    let err = load_or_create_master_key(&db_path).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("mode") && msg.contains("0600"),
        "expected permission error for world-readable, got: {msg}",
    );
}
