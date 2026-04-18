use red_cell_common::crypto::hash_password_sha3;
use red_cell_common::operator::{
    EventCode, InitConnectionCode, LoginInfo, Message, MessageHead, OperatorMessage,
};
use serde_json::json;
use uuid::Uuid;

use super::super::{AuthError, AuthService, AuthenticationFailure, AuthenticationResult};

#[tokio::test]
async fn authenticate_login_accepts_valid_hash_and_tracks_session() {
    let service =
        AuthService::from_profile(&super::profile()).expect("auth service should initialize");
    let connection_id = Uuid::new_v4();

    let result = service
        .authenticate_message(
            connection_id,
            &serde_json::to_string(&OperatorMessage::Login(Message {
                head: MessageHead {
                    event: EventCode::InitConnection,
                    user: "operator".to_owned(),
                    timestamp: String::new(),
                    one_time: String::new(),
                },
                info: LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            }))
            .expect("login message should serialize"),
        )
        .await
        .expect("login message should parse");

    let AuthenticationResult::Success(success) = result else {
        panic!("expected successful authentication");
    };

    assert_eq!(success.username, "operator");
    assert_eq!(service.session_count().await, 1);

    let by_connection = service
        .session_for_connection(connection_id)
        .await
        .expect("session should be associated to the connection");
    assert_eq!(by_connection.username, "operator");
    assert_eq!(by_connection.role, red_cell_common::config::OperatorRole::Operator);
    assert_eq!(by_connection.token, success.token);

    let by_token = service
        .session_for_token(&success.token)
        .await
        .expect("session should be retrievable by token");
    assert_eq!(by_token.connection_id, connection_id);
}

#[tokio::test]
async fn authenticate_login_rejects_unknown_users() {
    let service =
        AuthService::from_profile(&super::profile()).expect("auth service should initialize");
    let connection_id = Uuid::new_v4();

    let result = service
        .authenticate_login(
            connection_id,
            &LoginInfo { user: "ghost".to_owned(), password: hash_password_sha3("password1234") },
        )
        .await;

    assert_eq!(result, AuthenticationResult::Failure(AuthenticationFailure::InvalidCredentials));
    assert_eq!(service.session_count().await, 0);
}

#[tokio::test]
async fn authenticate_login_rejects_wrong_password_hash() {
    let service =
        AuthService::from_profile(&super::profile()).expect("auth service should initialize");

    let result = service
        .authenticate_login(
            Uuid::new_v4(),
            &LoginInfo { user: "operator".to_owned(), password: hash_password_sha3("wrong") },
        )
        .await;

    assert_eq!(result, AuthenticationResult::Failure(AuthenticationFailure::InvalidCredentials));
    assert_eq!(service.session_count().await, 0);
}

#[tokio::test]
async fn authenticate_login_accepts_uppercase_password_hash() {
    let service =
        AuthService::from_profile(&super::profile()).expect("auth service should initialize");

    let result = service
        .authenticate_login(
            Uuid::new_v4(),
            &LoginInfo {
                user: "operator".to_owned(),
                password: hash_password_sha3("password1234").to_ascii_uppercase(),
            },
        )
        .await;

    assert!(matches!(result, AuthenticationResult::Success(_)));
}

#[tokio::test]
async fn authenticate_message_rejects_non_login_messages() {
    let service =
        AuthService::from_profile(&super::profile()).expect("auth service should initialize");
    let payload = json!({
        "Head": { "Event": 1, "User": "operator" },
        "Body": { "SubEvent": 4, "Info": { "Any": "value" } }
    });

    let error = service
        .authenticate_message(Uuid::new_v4(), &payload.to_string())
        .await
        .expect_err("non-login message should be rejected");

    assert_eq!(error, AuthError::InvalidLoginMessage);
}

#[tokio::test]
async fn authenticate_message_rejects_invalid_json() {
    let service =
        AuthService::from_profile(&super::profile()).expect("auth service should initialize");

    let error = service
        .authenticate_message(Uuid::new_v4(), "not-valid-json{")
        .await
        .expect_err("invalid JSON should be rejected");

    assert!(
        matches!(error, AuthError::InvalidMessageJson(_)),
        "expected InvalidMessageJson, got {error:?}"
    );
    assert!(
        service.active_sessions().await.is_empty(),
        "no session should be created on invalid JSON"
    );
}

#[tokio::test]
async fn authenticate_message_accepts_password_sha3_alias() {
    let service =
        AuthService::from_profile(&super::profile()).expect("auth service should initialize");
    let connection_id = Uuid::new_v4();
    let payload = json!({
        "Head": {
            "Event": EventCode::InitConnection.as_u32(),
            "User": "operator"
        },
        "Body": {
            "SubEvent": InitConnectionCode::Login.as_u32(),
            "Info": {
                "User": "operator",
                "Password_SHA3": hash_password_sha3("password1234")
            }
        }
    });

    let result = service
        .authenticate_message(connection_id, &payload.to_string())
        .await
        .expect("login payload should parse");

    assert!(matches!(result, AuthenticationResult::Success(_)));
}

#[tokio::test]
async fn remove_connection_drops_associated_session() {
    let service =
        AuthService::from_profile(&super::profile()).expect("auth service should initialize");
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

    let AuthenticationResult::Success(success) = result else {
        panic!("expected successful authentication");
    };

    let removed =
        service.remove_connection(connection_id).await.expect("session should be removed");
    assert_eq!(removed.token, success.token);
    assert_eq!(service.session_count().await, 0);
    assert!(service.session_for_token(&success.token).await.is_none());
}

#[tokio::test]
async fn session_registry_replaces_old_session_on_same_connection_id() {
    let service =
        AuthService::from_profile(&super::profile()).expect("auth service should initialize");
    let connection_id = Uuid::new_v4();

    let first = service
        .authenticate_login(
            connection_id,
            &LoginInfo {
                user: "operator".to_owned(),
                password: hash_password_sha3("password1234"),
            },
        )
        .await;
    let AuthenticationResult::Success(first_success) = first else {
        panic!("expected successful first authentication");
    };

    assert_eq!(service.session_count().await, 1);

    let second = service
        .authenticate_login(
            connection_id,
            &LoginInfo {
                user: "operator".to_owned(),
                password: hash_password_sha3("password1234"),
            },
        )
        .await;
    let AuthenticationResult::Success(second_success) = second else {
        panic!("expected successful second authentication");
    };

    assert_eq!(service.session_count().await, 1);

    assert!(
        service.session_for_token(&first_success.token).await.is_none(),
        "stale token must not be retrievable after re-authentication"
    );

    let new_session = service
        .session_for_token(&second_success.token)
        .await
        .expect("new token must be retrievable");
    assert_eq!(new_session.connection_id, connection_id);
    assert_eq!(new_session.username, "operator");
}

#[tokio::test]
async fn authenticate_login_tracks_configured_role_on_session() {
    let service =
        AuthService::from_profile(&super::profile()).expect("auth service should initialize");
    let connection_id = Uuid::new_v4();

    let result = service
        .authenticate_login(
            connection_id,
            &LoginInfo { user: "analyst".to_owned(), password: hash_password_sha3("readonly") },
        )
        .await;

    assert!(matches!(result, AuthenticationResult::Success(_)));

    let session =
        service.session_for_connection(connection_id).await.expect("session should be stored");
    assert_eq!(session.role, red_cell_common::config::OperatorRole::Analyst);
}
