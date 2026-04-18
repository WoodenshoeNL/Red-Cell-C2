//! Tests for Profile::parse, Profile::from_reader, Profile::from_file,
//! and the ProfileError / ProfileValidationError display implementations.

use super::super::profile::is_valid_fqdn;
use super::super::*;

use super::{HAVOC_DATA_PROFILE, HAVOC_PROFILE, HTTP_SMB_PROFILE, WEBHOOK_PROFILE};

#[test]
fn parses_base_havoc_profile() {
    let profile = Profile::parse(HAVOC_PROFILE).expect("sample profile should parse");

    assert_eq!(profile.teamserver.host, "0.0.0.0");
    assert_eq!(profile.teamserver.port, 40056);
    assert_eq!(
        profile.teamserver.build.as_ref().and_then(|build| build.nasm.as_deref()),
        Some("/usr/bin/nasm")
    );
    assert_eq!(profile.operators.users.len(), 2);
    assert!(profile.operators.session_ttl_hours.is_none());
    assert!(profile.operators.idle_timeout_minutes.is_none());
    assert_eq!(
        profile.operators.users.get("Neo").map(|operator| operator.password.as_str()),
        Some("password1234")
    );
    assert_eq!(
        profile.operators.users.get("Neo").map(|operator| operator.role),
        Some(OperatorRole::Admin)
    );
    assert_eq!(profile.demon.sleep, Some(2));
    assert_eq!(profile.demon.jitter, Some(15));
    assert!(!profile.demon.trust_x_forwarded_for);
    assert_eq!(profile.demon.trusted_proxy_peers, vec!["127.0.0.1/32"]);
    assert_eq!(
        profile.demon.injection.as_ref().and_then(|injection| injection.spawn64.as_deref()),
        Some("C:\\Windows\\System32\\notepad.exe")
    );
    assert!(profile.listeners.http.is_empty());
    assert!(profile.listeners.smb.is_empty());
    assert!(profile.listeners.external.is_empty());
    assert!(profile.service.is_none());
    assert!(profile.webhook.is_none());
}

#[test]
fn parses_operators_session_policy_fields() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              SessionTtlHours = 48
              IdleTimeoutMinutes = 90
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile with operator session policy should parse");

    assert_eq!(profile.operators.session_ttl_hours, Some(48));
    assert_eq!(profile.operators.idle_timeout_minutes, Some(90));
    assert!(profile.validate().is_ok());
}

#[test]
fn rejects_zero_operators_session_ttl_hours() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              SessionTtlHours = 0
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("zero SessionTtlHours should fail validation");
    assert!(error.errors.iter().any(|message| message.contains("SessionTtlHours")));
}

#[test]
fn rejects_zero_operators_idle_timeout_minutes() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              IdleTimeoutMinutes = 0
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile should parse");

    let error = profile.validate().expect_err("zero IdleTimeoutMinutes should fail validation");
    assert!(error.errors.iter().any(|message| message.contains("IdleTimeoutMinutes")));
}

#[test]
fn parses_from_reader() {
    let profile = Profile::from_reader(HAVOC_DATA_PROFILE.as_bytes())
        .expect("embedded data profile should parse");

    assert_eq!(profile.teamserver.port, 40056);
    assert_eq!(profile.demon.sleep, Some(2));
    assert!(profile.teamserver.build.is_none());
}

#[test]
fn from_reader_rejects_malformed_hcl() {
    let result = Profile::from_reader("{{invalid hcl".as_bytes());
    assert!(result.is_err(), "malformed HCL must return an error");
    assert!(
        matches!(result.expect_err("expected Err"), ProfileError::Parse(_)),
        "error must be the Parse variant"
    );
}

#[test]
fn loads_profile_from_file() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let profile_path = temp_dir.path().join("profile.yaotl");

    std::fs::write(&profile_path, HAVOC_PROFILE).expect("profile fixture should be written");

    let profile = Profile::from_file(&profile_path).expect("profile should load from disk");

    assert_eq!(profile.teamserver.host, "0.0.0.0");
    assert_eq!(profile.teamserver.port, 40056);
}

#[test]
fn loads_all_embedded_profile_fixtures_from_disk() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let fixtures = [
        ("havoc.yaotl", HAVOC_PROFILE),
        ("http-smb.yaotl", HTTP_SMB_PROFILE),
        ("webhook.yaotl", WEBHOOK_PROFILE),
    ];

    for (name, fixture) in fixtures {
        let path = temp_dir.path().join(name);
        std::fs::write(&path, fixture).expect("profile fixture should be written");

        let profile = Profile::from_file(&path).expect("profile fixture should load");
        assert!(profile.validate().is_ok(), "fixture {name} should validate");
    }
}

#[test]
fn validates_sample_profile() {
    let profile = Profile::parse(HAVOC_PROFILE).expect("sample profile should parse");

    assert!(profile.validate().is_ok());
}

#[test]
fn rejects_invalid_profile_configuration() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = ""
              Port = 0
            }

            Operators {}

            Listeners {
              Http {
                Name = ""
                Hosts = []
                HostBind = ""
                HostRotation = ""
                PortBind = 0
              }
            }

            Demon {}
            "#,
    )
    .expect("invalid profile should still parse");

    let error = profile.validate().expect_err("validation should fail");

    assert!(error.errors.iter().any(|entry| entry.contains("Teamserver.Host")));
    assert!(error.errors.iter().any(|entry| entry.contains("Teamserver.Port")));
    assert!(error.errors.iter().any(|entry| entry.contains("Operators must define")));
    assert!(error.errors.iter().any(|entry| entry.contains("PortBind")));
}

#[test]
fn parse_rejects_malformed_hcl() {
    let result = Profile::parse("{completely invalid hcl]");
    assert!(result.is_err(), "malformed HCL must return an error");
    assert!(
        matches!(result.expect_err("expected Err"), ProfileError::Parse(_)),
        "error must be the Parse variant"
    );
}

#[test]
fn from_file_returns_error_for_nonexistent_path() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let missing_path = temp_dir.path().join("does_not_exist.yaotl");

    let result = Profile::from_file(&missing_path);
    assert!(result.is_err(), "missing file must return an error");

    match result.expect_err("expected Err") {
        ProfileError::Read { path, .. } => {
            assert_eq!(
                path,
                missing_path.display().to_string(),
                "error must carry the path that failed to open"
            );
        }
        other => panic!("expected ProfileError::Read, got {other:?}"),
    }
}

#[test]
fn parse_rejects_hcl_missing_teamserver_block() {
    // Valid HCL syntax but missing the required `Teamserver` block.
    let result = Profile::parse(
        r#"
            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
    );
    assert!(result.is_err(), "HCL missing Teamserver block must return an error");
    assert!(
        matches!(result.expect_err("expected Err"), ProfileError::Parse(_)),
        "error must be the Parse variant"
    );
}

#[test]
fn profile_error_parse_display_format() {
    // Trigger a parse error by passing garbage HCL.
    let err = Profile::parse("{{{{not valid hcl@@@@").expect_err("expected Err");
    let msg = err.to_string();
    assert!(msg.starts_with("failed to parse YAOTL profile:"), "unexpected Display output: {msg}");
}

#[test]
fn profile_error_read_display_contains_path() {
    let missing = "/tmp/red_cell_c2_nonexistent_profile_12345.hcl";
    let err = Profile::from_file(missing).expect_err("expected Err");
    let msg = err.to_string();
    assert!(
        msg.starts_with("failed to read YAOTL profile from"),
        "unexpected Display prefix: {msg}"
    );
    assert!(msg.contains(missing), "Display output must contain the path; got: {msg}");
}

#[test]
fn profile_validation_error_display_join_format() {
    let err = ProfileValidationError {
        errors: vec!["error one".to_owned(), "error two".to_owned(), "error three".to_owned()],
    };
    let msg = err.to_string();
    assert!(msg.starts_with("profile validation failed:"), "unexpected Display prefix: {msg}");
    assert!(
        msg.contains("error one; error two; error three"),
        "errors must be joined with \"; \"; got: {msg}"
    );
}

#[test]
fn profile_validation_error_display_single_error_format() {
    let err = ProfileValidationError { errors: vec!["single error".to_owned()] };

    assert_eq!(err.to_string(), "profile validation failed: single error");
}

#[test]
fn profile_validation_error_display_two_error_separator_format() {
    let err = ProfileValidationError {
        errors: vec!["first error".to_owned(), "second error".to_owned()],
    };

    assert_eq!(err.to_string(), "profile validation failed: first error; second error");
}

#[test]
fn profile_validation_error_display_empty_error_format() {
    let err = ProfileValidationError { errors: Vec::new() };

    assert_eq!(err.to_string(), "profile validation failed: ");
}

#[test]
fn is_valid_fqdn_accepts_valid_domains() {
    assert!(is_valid_fqdn("example.com"));
    assert!(is_valid_fqdn("c2.example.com"));
    assert!(is_valid_fqdn("sub.domain.example.com"));
    assert!(is_valid_fqdn("example.com."));
    assert!(is_valid_fqdn("my-domain.example.com"));
}

#[test]
fn is_valid_fqdn_rejects_invalid_domains() {
    assert!(!is_valid_fqdn(""));
    assert!(!is_valid_fqdn("localhost"));
    assert!(!is_valid_fqdn(".example.com"));
    assert!(!is_valid_fqdn("example..com"));
    assert!(!is_valid_fqdn("-example.com"));
    assert!(!is_valid_fqdn("example-.com"));
    assert!(!is_valid_fqdn("exam ple.com"));
    assert!(!is_valid_fqdn("example.com/path"));
}
