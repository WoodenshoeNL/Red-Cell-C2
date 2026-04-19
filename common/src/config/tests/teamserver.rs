//! Tests for teamserver configuration parsing and validation,
//! including Demon block config, logging, TLS, and agent limits.

use super::super::*;

use zeroize::Zeroizing;

#[test]
fn parses_teamserver_plugins_dir() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              PluginsDir = "plugins"
              MaxDownloadBytes = 1048576
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    assert_eq!(profile.teamserver.plugins_dir.as_deref(), Some("plugins"));
    assert_eq!(profile.teamserver.max_download_bytes, Some(1_048_576));
    assert_eq!(profile.teamserver.max_registered_agents, None);
    assert_eq!(profile.teamserver.drain_timeout_secs, None);
}

#[test]
fn parses_teamserver_download_and_pivot_limits() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              MaxConcurrentDownloadsPerAgent = 8
              MaxAggregateDownloadBytes = 268435456
              MaxPivotChainDepth = 5
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    assert_eq!(profile.teamserver.max_concurrent_downloads_per_agent, Some(8));
    assert_eq!(profile.teamserver.max_aggregate_download_bytes, Some(268_435_456));
    assert_eq!(profile.teamserver.max_pivot_chain_depth, Some(5));
}

#[test]
fn parses_teamserver_download_and_pivot_limits_defaults_to_none_when_absent() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    assert_eq!(profile.teamserver.max_concurrent_downloads_per_agent, None);
    assert_eq!(profile.teamserver.max_aggregate_download_bytes, None);
    assert_eq!(profile.teamserver.max_pivot_chain_depth, None);
}

#[test]
fn parses_teamserver_max_registered_agents() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              MaxRegisteredAgents = 2048
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    assert_eq!(profile.teamserver.max_registered_agents, Some(2_048));
}

#[test]
fn parses_teamserver_drain_timeout() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              DrainTimeoutSecs = 45
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    assert_eq!(profile.teamserver.drain_timeout_secs, Some(45));
}

#[test]
fn parses_teamserver_logging_configuration() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              Logging {
                Level = "red_cell=debug,tower_http=info"
                Format = "Json"

                File {
                  Directory = "logs"
                  Prefix = "teamserver.log"
                  Rotation = "Hourly"
                }
              }
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let logging = profile.teamserver.logging.expect("logging config should exist");
    assert_eq!(logging.level.as_deref(), Some("red_cell=debug,tower_http=info"));
    assert_eq!(logging.format, Some(LogFormat::Json));

    let file = logging.file.expect("file logging config should exist");
    assert_eq!(file.directory, "logs");
    assert_eq!(file.prefix, "teamserver.log");
    assert_eq!(file.rotation, Some(LogRotation::Hourly));
}

#[test]
fn rejects_empty_teamserver_plugins_dir() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              PluginsDir = "   "
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("PluginsDir")));
}

#[test]
fn rejects_zero_max_registered_agents() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              MaxRegisteredAgents = 0
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("MaxRegisteredAgents")));
}

#[test]
fn rejects_zero_drain_timeout_secs() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              DrainTimeoutSecs = 0
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("DrainTimeoutSecs")));
}

#[test]
fn parses_agent_timeout_secs() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              AgentTimeoutSecs = 90
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {
              Sleep = 5
            }
            "#,
    )
    .expect("profile should parse");

    assert_eq!(profile.teamserver.agent_timeout_secs, Some(90));
}

#[test]
fn rejects_zero_agent_timeout_secs() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              AgentTimeoutSecs = 0
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("AgentTimeoutSecs")));
}

#[test]
fn rejects_invalid_teamserver_logging_configuration() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              Logging {
                Level = "   "

                File {
                  Directory = " "
                  Prefix = ""
                }
              }
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("Logging.Level")));
    assert!(error.errors.iter().any(|message| message.contains("Logging.File.Directory")));
    assert!(error.errors.iter().any(|message| message.contains("Logging.File.Prefix")));
}

#[test]
fn rejects_zero_max_download_bytes() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              MaxDownloadBytes = 0
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(error.errors.iter().any(|message| message.contains("MaxDownloadBytes")));
}

#[test]
fn rejects_empty_init_secret() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {
              InitSecret = ""
            }
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("empty InitSecret should be invalid");
    assert!(
        error.errors.iter().any(|msg| msg.contains("InitSecret") && msg.contains("empty")),
        "expected an InitSecret error, got: {:?}",
        error.errors
    );
}

#[test]
fn rejects_init_secret_shorter_than_minimum() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {
              InitSecret = "tooshort"
            }
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("short InitSecret should be invalid");
    assert!(
        error.errors.iter().any(|msg| msg.contains("InitSecret") && msg.contains("minimum")),
        "expected a minimum-length InitSecret error, got: {:?}",
        error.errors
    );
}

#[test]
fn accepts_init_secret_at_minimum_length() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {
              InitSecret = "exactly16bytesok"
            }
            "#,
    )
    .expect("profile should parse");

    profile.validate().expect("16-byte InitSecret should be accepted");
}

#[test]
fn accepts_absent_init_secret() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    profile.validate().expect("absent InitSecret should be accepted");
}

#[test]
fn rejects_both_init_secret_and_init_secrets() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {
              InitSecret = "exactly16bytesok"
              InitSecrets = [
                { Version = 1, Secret = "exactly16bytesok" }
              ]
            }
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("both fields set should be invalid");
    assert!(
        error.errors.iter().any(|msg| msg.contains("mutually exclusive")),
        "expected a mutually-exclusive error, got: {:?}",
        error.errors
    );
}

#[test]
fn rejects_init_secrets_with_duplicate_version() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {
              InitSecrets = [
                { Version = 1, Secret = "exactly16bytesok" },
                { Version = 1, Secret = "another16bytes!!" }
              ]
            }
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("duplicate version should be invalid");
    assert!(
        error.errors.iter().any(|msg| msg.contains("duplicate version")),
        "expected a duplicate-version error, got: {:?}",
        error.errors
    );
}

#[test]
fn rejects_init_secrets_with_short_secret() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {
              InitSecrets = [
                { Version = 1, Secret = "tooshort" }
              ]
            }
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("short secret in InitSecrets should be invalid");
    assert!(
        error.errors.iter().any(|msg| msg.contains("InitSecrets") && msg.contains("minimum")),
        "expected a minimum-length error in InitSecrets, got: {:?}",
        error.errors
    );
}

#[test]
fn accepts_valid_init_secrets() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {
              InitSecrets = [
                { Version = 1, Secret = "old-secret-exactly16" },
                { Version = 2, Secret = "new-secret-exactly16" }
              ]
            }
            "#,
    )
    .expect("profile should parse");

    profile.validate().expect("valid InitSecrets list should be accepted");
}

fn demon_config_with_secret(secret: Option<&str>) -> DemonConfig {
    DemonConfig {
        sleep: None,
        jitter: None,
        indirect_syscall: false,
        stack_duplication: false,
        sleep_technique: None,
        proxy_loading: None,
        amsi_etw_patching: None,
        injection: None,
        dotnet_name_pipe: None,
        binary: None,
        init_secret: secret.map(|s| Zeroizing::new(s.to_owned())),
        init_secrets: Vec::new(),
        trust_x_forwarded_for: false,
        trusted_proxy_peers: vec![],
        heap_enc: true,
        allow_legacy_ctr: false,
        job_execution: "thread".to_owned(),
        stomp_dll: None,
    }
}

#[test]
fn demon_config_debug_redacts_init_secret() {
    let config = demon_config_with_secret(Some("hkdf-super-secret"));

    let debug = format!("{config:?}");

    assert!(debug.contains("DemonConfig"));
    assert!(debug.contains("init_secret: Some(\"[redacted]\")"));
    assert!(!debug.contains("hkdf-super-secret"));
}

#[test]
fn demon_config_debug_none_init_secret() {
    let config = demon_config_with_secret(None);

    let debug = format!("{config:?}");

    assert!(debug.contains("init_secret: None"));
}

#[test]
fn demon_config_amsi_etw_canonical_alias_deserialises() {
    // ARC-01: the profile may use `AmsiEtw` (canonical) or `AmsiEtwPatching` (legacy).
    // Both must deserialise to the same `amsi_etw_patching` field.
    const PROFILE_CANONICAL: &str = r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056
            }
            Operators {
              user "test" { Password = "test" }
            }
            Demon {
              AmsiEtw = "patch"
            }
        "#;
    const PROFILE_LEGACY: &str = r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056
            }
            Operators {
              user "test" { Password = "test" }
            }
            Demon {
              AmsiEtwPatching = "hwbp"
            }
        "#;

    let canonical =
        Profile::parse(PROFILE_CANONICAL).expect("canonical AmsiEtw key should deserialise");
    let legacy =
        Profile::parse(PROFILE_LEGACY).expect("legacy AmsiEtwPatching key should deserialise");

    assert_eq!(canonical.demon.amsi_etw_patching.as_deref(), Some("patch"));
    assert_eq!(legacy.demon.amsi_etw_patching.as_deref(), Some("hwbp"));
}

#[test]
fn rejects_teamserver_cert_file_not_found() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              Cert {
                Cert = "/nonexistent/path/cert.pem"
                Key = "/nonexistent/path/key.pem"
              }
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|m| m.contains("Teamserver.Cert.Cert file not found")),
        "expected cert file not found error; got: {error:?}"
    );
    assert!(
        error.errors.iter().any(|m| m.contains("Teamserver.Cert.Key file not found")),
        "expected key file not found error; got: {error:?}"
    );
}

#[test]
fn accepts_teamserver_cert_paths_that_exist() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, b"fake-cert").expect("write cert");
    std::fs::write(&key_path, b"fake-key").expect("write key");

    let hcl = format!(
        r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
              Cert {{
                Cert = "{}"
                Key = "{}"
              }}
            }}

            Operators {{
              user "neo" {{
                Password = "password1234"
              }}
            }}

            Demon {{}}
            "#,
        cert_path.display(),
        key_path.display()
    );

    let profile = Profile::parse(&hcl).expect("profile should parse");
    profile.validate().expect("profile with existing cert paths should pass validation");
}

#[test]
fn parses_teamserver_tls_certificate_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("server.crt");
    let key_path = dir.path().join("server.key");
    std::fs::write(&cert_path, b"fake-cert").expect("write cert");
    std::fs::write(&key_path, b"fake-key").expect("write key");

    let hcl = format!(
        r#"
            Teamserver {{
              Host = "0.0.0.0"
              Port = 40056

              Cert {{
                Cert = "{}"
                Key = "{}"
              }}
            }}

            Operators {{
              user "Neo" {{
                Password = "password1234"
              }}
            }}

            Listeners {{}}

            Demon {{}}
            "#,
        cert_path.display(),
        key_path.display()
    );

    let profile = Profile::parse(&hcl).expect("profile with teamserver cert block should parse");

    let cert = profile.teamserver.cert.as_ref().expect("teamserver cert block should be present");

    assert_eq!(cert.cert, cert_path.display().to_string());
    assert_eq!(cert.key, key_path.display().to_string());

    profile.validate().expect("profile with valid cert paths should pass validation");
}

#[test]
fn rejects_teamserver_with_blank_certificate_path() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056

              Cert {
                Cert = "   "
                Key = "/tmp/server.key"
              }
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {}

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|message| message.contains("Teamserver.Cert.Cert")),
        "expected error about blank Teamserver.Cert.Cert path, got: {error:?}"
    );
}

#[test]
fn rejects_teamserver_with_blank_certificate_key_path() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056

              Cert {
                Cert = "/tmp/server.crt"
                Key = "   "
              }
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {}

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|message| message.contains("Teamserver.Cert.Key")),
        "expected error about blank Teamserver.Cert.Key path, got: {error:?}"
    );
}

#[test]
fn rejects_teamserver_with_both_blank_certificate_paths() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056

              Cert {
                Cert = ""
                Key = ""
              }
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {}

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("profile should be invalid");
    assert!(
        error.errors.iter().any(|message| message.contains("Teamserver.Cert.Cert")),
        "expected Cert path error, got: {error:?}"
    );
    assert!(
        error.errors.iter().any(|message| message.contains("Teamserver.Cert.Key")),
        "expected Key path error, got: {error:?}"
    );
}
