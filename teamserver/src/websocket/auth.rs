use std::net::IpAddr;

use axum::extract::ws::{Message as WsMessage, WebSocket};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use tracing::{debug, warn};
use uuid::Uuid;

use super::connection::{
    AUTHENTICATION_FRAME_TIMEOUT, FAILED_LOGIN_DELAY, LoginRateLimiter, OperatorConnectionManager,
    send_login_error, send_operator_message,
};
use super::lifecycle::log_operator_action;
use crate::{
    AuditResultStatus, AuditWebhookNotifier, AuthError, AuthService, AuthVector,
    AuthenticationFailure, AuthenticationResult, Database, audit_details, login_failure_message,
    login_parameters, login_success_message, parameter_object,
};

pub(super) async fn handle_authentication(
    auth: &AuthService,
    connections: &OperatorConnectionManager,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    rate_limiter: &LoginRateLimiter,
    connection_id: Uuid,
    client_ip: IpAddr,
    socket: &mut WebSocket,
) -> Result<(), ()> {
    if !rate_limiter.try_acquire(client_ip).await {
        warn!(
            %connection_id,
            %client_ip,
            "login rate limit exceeded — rejecting connection"
        );
        send_login_error(socket, "", AuthenticationFailure::InvalidCredentials, connection_id)
            .await;
        return Err(());
    }

    let frame = match tokio::time::timeout(AUTHENTICATION_FRAME_TIMEOUT, socket.recv()).await {
        Ok(Some(frame)) => frame,
        Ok(None) => {
            warn!(%connection_id, "operator websocket closed before authentication");
            return Err(());
        }
        Err(_) => {
            warn!(
                %connection_id,
                timeout_secs = AUTHENTICATION_FRAME_TIMEOUT.as_secs(),
                "operator websocket authentication timed out"
            );
            log_operator_action(
                database,
                webhooks,
                "",
                "operator.session_timeout",
                "operator",
                None,
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("session_timeout"),
                    Some(parameter_object([(
                        "connection_id",
                        Value::String(connection_id.to_string()),
                    )])),
                ),
            )
            .await;
            if let Err(e) = socket.send(WsMessage::Close(None)).await {
                debug!(%e, "session timeout: failed to send close frame");
            }
            return Err(());
        }
    };

    let message = match frame {
        Ok(WsMessage::Text(payload)) => payload,
        Ok(WsMessage::Close(_)) => return Err(()),
        Ok(other) => {
            warn!(%connection_id, frame = ?other, "operator websocket requires text login frame");
            if let Err(e) = send_operator_message(
                socket,
                &login_failure_message("", &AuthenticationFailure::InvalidCredentials),
            )
            .await
            {
                debug!(%e, "auth: failed to send login failure for non-text frame");
            }
            if let Err(e) = socket.send(WsMessage::Close(None)).await {
                debug!(%e, "auth: failed to send close frame for non-text frame");
            }
            return Err(());
        }
        Err(error) => {
            warn!(%connection_id, %error, "failed to receive operator authentication frame");
            return Err(());
        }
    };

    let login_user = serde_json::from_str::<OperatorMessage>(message.as_str())
        .ok()
        .and_then(|message| match message {
            OperatorMessage::Login(message) => Some(message.info.user),
            _ => None,
        })
        .unwrap_or_default();

    let response = match auth.authenticate_message(connection_id, message.as_str()).await {
        Ok(AuthenticationResult::Success(success)) => {
            connections.authenticate(connection_id, success.username.clone()).await;
            rate_limiter.record_success(client_ip).await;
            log_operator_action(
                database,
                webhooks,
                &success.username,
                "operator.login",
                "operator",
                Some(success.username.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    None,
                    Some("login"),
                    Some(login_parameters(
                        &success.username,
                        &connection_id,
                        AuthVector::Websocket,
                    )),
                ),
            )
            .await;
            login_success_message(&success.username, &success.token)
        }
        Ok(AuthenticationResult::Failure(failure)) => {
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            log_operator_action(
                database,
                webhooks,
                &login_user,
                "operator.login",
                "operator",
                (!login_user.is_empty()).then_some(login_user.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("login"),
                    Some(login_parameters(&login_user, &connection_id, AuthVector::Websocket)),
                ),
            )
            .await;
            send_login_error(socket, "", failure, connection_id).await;
            return Err(());
        }
        Err(AuthError::InvalidLoginMessage) => {
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            log_operator_action(
                database,
                webhooks,
                &login_user,
                "operator.login",
                "operator",
                (!login_user.is_empty()).then_some(login_user.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("login"),
                    Some(login_parameters(&login_user, &connection_id, AuthVector::Websocket)),
                ),
            )
            .await;
            send_login_error(socket, "", AuthenticationFailure::InvalidCredentials, connection_id)
                .await;
            return Err(());
        }
        Err(AuthError::InvalidMessageJson(error)) => {
            warn!(%connection_id, %error, "failed to parse operator login message");
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            log_operator_action(
                database,
                webhooks,
                "",
                "operator.login",
                "operator",
                None,
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("login"),
                    Some(parameter_object([
                        ("connection_id", Value::String(connection_id.to_string())),
                        ("error", Value::String(error)),
                    ])),
                ),
            )
            .await;
            send_login_error(socket, "", AuthenticationFailure::InvalidCredentials, connection_id)
                .await;
            return Err(());
        }
        Err(
            AuthError::DuplicateUser { .. }
            | AuthError::EmptyUsername
            | AuthError::EmptyPassword
            | AuthError::OperatorNotFound { .. }
            | AuthError::ProfileOperator { .. },
        ) => {
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            send_login_error(socket, "", AuthenticationFailure::InvalidCredentials, connection_id)
                .await;
            return Err(());
        }
        Err(AuthError::PasswordVerifier(error)) => {
            warn!(%connection_id, %error, "operator authentication verifier error");
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            send_login_error(socket, "", AuthenticationFailure::InvalidCredentials, connection_id)
                .await;
            return Err(());
        }
        Err(AuthError::Persistence(error)) | Err(AuthError::AuditLog(error)) => {
            warn!(%connection_id, %error, "operator authentication backing store error");
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            send_login_error(socket, "", AuthenticationFailure::InvalidCredentials, connection_id)
                .await;
            return Err(());
        }
    };

    if send_operator_message(socket, &response).await.is_err() {
        return Err(());
    }

    Ok(())
}
