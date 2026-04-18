use red_cell_common::config::Profile;
use red_cell_common::crypto::hash_password_sha3;
use red_cell_common::operator::LoginInfo;
use uuid::Uuid;

use super::super::{AuthService, AuthenticationFailure, AuthenticationResult};

// ── Session cap / concurrency limits ─────────────────────────────────────────

#[tokio::test]
async fn authenticate_login_rejects_when_per_account_cap_reached() {
    use super::super::MAX_SESSIONS_PER_ACCOUNT;

    let service =
        AuthService::from_profile(&super::profile()).expect("auth service should initialize");

    for _ in 0..MAX_SESSIONS_PER_ACCOUNT {
        let result = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        assert!(matches!(result, AuthenticationResult::Success(_)));
    }

    assert_eq!(service.session_count().await, MAX_SESSIONS_PER_ACCOUNT);

    let result = service
        .authenticate_login(
            Uuid::new_v4(),
            &LoginInfo {
                user: "operator".to_owned(),
                password: hash_password_sha3("password1234"),
            },
        )
        .await;

    assert_eq!(result, AuthenticationResult::Failure(AuthenticationFailure::SessionCapExceeded));
    assert_eq!(service.session_count().await, MAX_SESSIONS_PER_ACCOUNT);
}

#[tokio::test]
async fn authenticate_login_rejects_when_global_cap_reached() {
    use super::super::{MAX_OPERATOR_SESSIONS, MAX_SESSIONS_PER_ACCOUNT};

    let accounts_needed = MAX_OPERATOR_SESSIONS.div_ceil(MAX_SESSIONS_PER_ACCOUNT);

    let mut hcl =
        String::from("Teamserver {\n  Host = \"127.0.0.1\"\n  Port = 40057\n}\nOperators {\n");
    for i in 0..accounts_needed {
        hcl.push_str(&format!(
            "  user \"op{i}\" {{\n    Password = \"pass{i}\"\n    Role = \"Operator\"\n  }}\n"
        ));
    }
    hcl.push_str("}\nDemon {}");

    let profile = Profile::parse(&hcl).expect("test profile should parse");
    let service = AuthService::from_profile(&profile).expect("auth service should initialize");

    let mut sessions_created = 0usize;
    'outer: for i in 0..accounts_needed {
        let username = format!("op{i}");
        let password = format!("pass{i}");
        for _ in 0..MAX_SESSIONS_PER_ACCOUNT {
            if sessions_created >= MAX_OPERATOR_SESSIONS {
                break 'outer;
            }
            let result = service
                .authenticate_login(
                    Uuid::new_v4(),
                    &LoginInfo { user: username.clone(), password: hash_password_sha3(&password) },
                )
                .await;
            assert!(
                matches!(result, AuthenticationResult::Success(_)),
                "session {sessions_created} should succeed"
            );
            sessions_created += 1;
        }
    }

    assert_eq!(service.session_count().await, MAX_OPERATOR_SESSIONS);

    let result = service
        .authenticate_login(
            Uuid::new_v4(),
            &LoginInfo { user: "op0".to_owned(), password: hash_password_sha3("pass0") },
        )
        .await;

    assert_eq!(result, AuthenticationResult::Failure(AuthenticationFailure::SessionCapExceeded));
    assert_eq!(service.session_count().await, MAX_OPERATOR_SESSIONS);
}

#[tokio::test]
async fn authenticate_login_succeeds_after_session_removed() {
    use super::super::MAX_SESSIONS_PER_ACCOUNT;

    let service =
        AuthService::from_profile(&super::profile()).expect("auth service should initialize");

    let mut connection_ids: Vec<Uuid> = Vec::new();

    for _ in 0..MAX_SESSIONS_PER_ACCOUNT {
        let conn = Uuid::new_v4();
        connection_ids.push(conn);
        let result = service
            .authenticate_login(
                conn,
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        assert!(matches!(result, AuthenticationResult::Success(_)));
    }

    let over_cap = service
        .authenticate_login(
            Uuid::new_v4(),
            &LoginInfo {
                user: "operator".to_owned(),
                password: hash_password_sha3("password1234"),
            },
        )
        .await;
    assert_eq!(over_cap, AuthenticationResult::Failure(AuthenticationFailure::SessionCapExceeded));

    service.remove_connection(connection_ids[0]).await;
    assert_eq!(service.session_count().await, MAX_SESSIONS_PER_ACCOUNT - 1);

    let result = service
        .authenticate_login(
            Uuid::new_v4(),
            &LoginInfo {
                user: "operator".to_owned(),
                password: hash_password_sha3("password1234"),
            },
        )
        .await;
    assert!(matches!(result, AuthenticationResult::Success(_)));
}

// ── Session expiry / idle-timeout ─────────────────────────────────────────

#[tokio::test]
async fn auth_service_has_default_session_policy() {
    let service =
        AuthService::from_profile(&super::profile()).expect("auth service should initialize");
    let policy = service.session_policy();
    assert_eq!(
        policy.ttl,
        Some(std::time::Duration::from_secs(24 * 60 * 60)),
        "default session TTL should be 24h"
    );
    assert_eq!(
        policy.idle_timeout,
        Some(std::time::Duration::from_secs(30 * 60)),
        "default idle timeout should be 30 min"
    );
}

#[tokio::test]
async fn from_profile_applies_operators_session_policy_from_hcl() {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          SessionTtlHours = 48
          IdleTimeoutMinutes = 45
          user "operator" {
            Password = "password1234"
            Role = "Operator"
          }
        }

        Demon {}
        "#,
    )
    .expect("profile should parse");

    let service = AuthService::from_profile(&profile).expect("auth service should initialize");
    let policy = service.session_policy();
    assert_eq!(policy.ttl, Some(std::time::Duration::from_secs(48 * 3600)));
    assert_eq!(policy.idle_timeout, Some(std::time::Duration::from_secs(45 * 60)));
}

#[tokio::test]
async fn with_session_policy_overrides_default() {
    use super::super::SessionPolicy;
    let service = AuthService::from_profile(&super::profile())
        .expect("auth service should initialize")
        .with_session_policy(SessionPolicy {
            ttl: Some(std::time::Duration::from_secs(10)),
            idle_timeout: Some(std::time::Duration::from_secs(1)),
        });
    let policy = service.session_policy();
    assert_eq!(policy.ttl, Some(std::time::Duration::from_secs(10)));
    assert_eq!(policy.idle_timeout, Some(std::time::Duration::from_secs(1)));
}

#[tokio::test]
async fn touch_session_activity_refreshes_last_activity_for_live_session() {
    use super::super::{SessionActivity, SessionPolicy};

    let service = AuthService::from_profile(&super::profile())
        .expect("auth service should initialize")
        .with_session_policy(SessionPolicy {
            ttl: Some(std::time::Duration::from_secs(3600)),
            idle_timeout: Some(std::time::Duration::from_secs(60)),
        });
    let connection_id = Uuid::new_v4();
    let result = service
        .authenticate_login(
            connection_id,
            &LoginInfo {
                user: "operator".to_owned(),
                password: hash_password_sha3("password1234"),
            },
        )
        .await;
    assert!(matches!(result, AuthenticationResult::Success(_)));

    let before =
        service.session_for_connection(connection_id).await.expect("session should be present");
    let later = before.last_activity_at + std::time::Duration::from_secs(30);
    assert_eq!(service.touch_session_activity_at(connection_id, later).await, SessionActivity::Ok,);

    let after =
        service.session_for_connection(connection_id).await.expect("session should still exist");
    assert_eq!(after.last_activity_at, later);
    assert_eq!(after.created_at, before.created_at);
}

#[tokio::test]
async fn touch_session_activity_expires_session_past_ttl() {
    use super::super::{SessionActivity, SessionExpiryReason, SessionPolicy};

    let service = AuthService::from_profile(&super::profile())
        .expect("auth service should initialize")
        .with_session_policy(SessionPolicy {
            ttl: Some(std::time::Duration::from_secs(10)),
            idle_timeout: Some(std::time::Duration::from_secs(600)),
        });
    let connection_id = Uuid::new_v4();
    let login = service
        .authenticate_login(
            connection_id,
            &LoginInfo {
                user: "operator".to_owned(),
                password: hash_password_sha3("password1234"),
            },
        )
        .await;
    let AuthenticationResult::Success(success) = login else {
        panic!("expected success");
    };

    let session =
        service.session_for_connection(connection_id).await.expect("session should be present");
    let past_ttl = session.created_at + std::time::Duration::from_secs(11);

    match service.touch_session_activity_at(connection_id, past_ttl).await {
        SessionActivity::Expired { reason, username } => {
            assert_eq!(reason, SessionExpiryReason::TtlExceeded);
            assert_eq!(username, "operator");
        }
        other => panic!("expected Expired, got {other:?}"),
    }

    assert!(
        service.session_for_token(&success.token).await.is_none(),
        "expired session must be removed from registry"
    );
    assert_eq!(service.session_count().await, 0);
}

#[tokio::test]
async fn touch_session_activity_expires_session_past_idle_timeout() {
    use super::super::{SessionActivity, SessionExpiryReason, SessionPolicy};

    let service = AuthService::from_profile(&super::profile())
        .expect("auth service should initialize")
        .with_session_policy(SessionPolicy {
            ttl: Some(std::time::Duration::from_secs(3600)),
            idle_timeout: Some(std::time::Duration::from_secs(60)),
        });
    let connection_id = Uuid::new_v4();
    let login = service
        .authenticate_login(
            connection_id,
            &LoginInfo { user: "analyst".to_owned(), password: hash_password_sha3("readonly") },
        )
        .await;
    assert!(matches!(login, AuthenticationResult::Success(_)));

    let session =
        service.session_for_connection(connection_id).await.expect("session should be present");
    let past_idle = session.last_activity_at + std::time::Duration::from_secs(61);

    match service.touch_session_activity_at(connection_id, past_idle).await {
        SessionActivity::Expired { reason, username } => {
            assert_eq!(reason, SessionExpiryReason::IdleTimeout);
            assert_eq!(username, "analyst");
        }
        other => panic!("expected Expired, got {other:?}"),
    }
    assert_eq!(service.session_count().await, 0);
}

#[tokio::test]
async fn touch_session_activity_preserves_session_when_policy_unbounded() {
    use super::super::{SessionActivity, SessionPolicy};

    let service = AuthService::from_profile(&super::profile())
        .expect("auth service should initialize")
        .with_session_policy(SessionPolicy::unbounded());
    let connection_id = Uuid::new_v4();
    let login = service
        .authenticate_login(
            connection_id,
            &LoginInfo {
                user: "operator".to_owned(),
                password: hash_password_sha3("password1234"),
            },
        )
        .await;
    assert!(matches!(login, AuthenticationResult::Success(_)));

    let session =
        service.session_for_connection(connection_id).await.expect("session should be present");
    let far_future = session.created_at + std::time::Duration::from_secs(7 * 24 * 3600);

    assert_eq!(
        service.touch_session_activity_at(connection_id, far_future).await,
        SessionActivity::Ok,
    );
    assert_eq!(service.session_count().await, 1);
}

#[tokio::test]
async fn touch_session_activity_after_expiry_returns_not_found() {
    use super::super::{SessionActivity, SessionPolicy};

    let service = AuthService::from_profile(&super::profile())
        .expect("auth service should initialize")
        .with_session_policy(SessionPolicy {
            ttl: Some(std::time::Duration::from_secs(10)),
            idle_timeout: None,
        });
    let connection_id = Uuid::new_v4();
    let login = service
        .authenticate_login(
            connection_id,
            &LoginInfo {
                user: "operator".to_owned(),
                password: hash_password_sha3("password1234"),
            },
        )
        .await;
    assert!(matches!(login, AuthenticationResult::Success(_)));

    let session =
        service.session_for_connection(connection_id).await.expect("session should be present");
    let future = session.created_at + std::time::Duration::from_secs(20);

    assert!(matches!(
        service.touch_session_activity_at(connection_id, future).await,
        SessionActivity::Expired { .. },
    ));
    assert_eq!(
        service.touch_session_activity_at(connection_id, future).await,
        SessionActivity::NotFound,
        "second call after expiry must report NotFound",
    );
}

#[tokio::test]
async fn touch_session_activity_refresh_extends_idle_window() {
    use super::super::{SessionActivity, SessionPolicy};

    let service = AuthService::from_profile(&super::profile())
        .expect("auth service should initialize")
        .with_session_policy(SessionPolicy {
            ttl: Some(std::time::Duration::from_secs(3600)),
            idle_timeout: Some(std::time::Duration::from_secs(60)),
        });
    let connection_id = Uuid::new_v4();
    let login = service
        .authenticate_login(
            connection_id,
            &LoginInfo {
                user: "operator".to_owned(),
                password: hash_password_sha3("password1234"),
            },
        )
        .await;
    assert!(matches!(login, AuthenticationResult::Success(_)));

    let session =
        service.session_for_connection(connection_id).await.expect("session should be present");
    // 40 seconds after login — within idle window.
    let first_tick = session.last_activity_at + std::time::Duration::from_secs(40);
    assert_eq!(
        service.touch_session_activity_at(connection_id, first_tick).await,
        SessionActivity::Ok,
    );

    // 40 seconds after the previous tick (80 seconds since login) — would
    // have exceeded the 60s idle window, but the previous tick refreshed
    // last_activity_at so the session is still valid.
    let second_tick = first_tick + std::time::Duration::from_secs(40);
    assert_eq!(
        service.touch_session_activity_at(connection_id, second_tick).await,
        SessionActivity::Ok,
    );
}
