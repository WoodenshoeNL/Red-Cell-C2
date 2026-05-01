//! Listener start/stop lifecycle and per-protocol runtime spawning.
//!
//! Implements the `start`, `stop`, and internal `*_locked` variants on
//! [`super::ListenerManager`], plus the free function
//! [`spawn_managed_listener_task`] that wraps a listener future in a Tokio
//! task and persists the terminal state when it exits.

use std::collections::BTreeMap;
use std::sync::Arc;

use red_cell_common::ListenerConfig;
use red_cell_common::operator::{
    EventCode, Message, MessageHead, OperatorMessage, TeamserverLogInfo,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{info, instrument, warn};

use super::ListenerManager;
use super::ListenerManagerError;
use super::ListenerRuntimeFuture;
use crate::{AuditLogEntry, ListenerRepository, ListenerStatus};

impl ListenerManager {
    /// Start the named listener runtime.
    #[instrument(skip(self), fields(listener_name = %name))]
    pub async fn start(&self, name: &str) -> Result<super::ListenerSummary, ListenerManagerError> {
        let _guard = self.operations.lock().await;
        self.start_locked(name).await
    }

    /// Stop the named listener runtime.
    #[instrument(skip(self), fields(listener_name = %name))]
    pub async fn stop(&self, name: &str) -> Result<super::ListenerSummary, ListenerManagerError> {
        let _guard = self.operations.lock().await;
        self.stop_locked(name).await
    }

    pub(super) async fn start_locked(
        &self,
        name: &str,
    ) -> Result<super::ListenerSummary, ListenerManagerError> {
        let repository = self.repository();
        let listener = repository
            .get(name)
            .await?
            .ok_or_else(|| ListenerManagerError::ListenerNotFound { name: name.to_owned() })?;
        self.prune_finished_handle(name).await;
        if self.active_handles.read().await.contains_key(name) {
            return Err(ListenerManagerError::ListenerAlreadyRunning { name: name.to_owned() });
        }

        match self.spawn_listener_runtime(&listener.config).await {
            Ok(handle) => {
                self.active_handles.write().await.insert(name.to_owned(), handle);
                repository.set_state(name, ListenerStatus::Running, None).await?;
                info!(listener = name, protocol = %listener.protocol, "listener started");
                for warning in super::super::opsec::opsec_warnings(&listener.config) {
                    warn!(listener = name, "{warning}");
                    self.events.broadcast(OperatorMessage::TeamserverLog(Message {
                        head: MessageHead {
                            event: EventCode::Teamserver,
                            user: String::new(),
                            timestamp: String::new(),
                            one_time: String::new(),
                        },
                        info: TeamserverLogInfo { text: warning.to_owned() },
                    }));
                    let occurred_at = OffsetDateTime::now_utc()
                        .format(&Rfc3339)
                        .unwrap_or_else(|_| String::from("unknown"));
                    if let Err(err) = self
                        .database
                        .audit_log()
                        .create(&AuditLogEntry {
                            id: None,
                            actor: "teamserver".to_owned(),
                            action: "opsec_warning".to_owned(),
                            target_kind: "listener".to_owned(),
                            target_id: Some(name.to_owned()),
                            details: Some(serde_json::json!({ "warning": warning })),
                            occurred_at,
                        })
                        .await
                    {
                        warn!(
                            listener = name,
                            error = %err,
                            "failed to write opsec warning audit log entry"
                        );
                    }
                }
                self.summary(name).await
            }
            Err(error) => {
                let error_text = error.to_string();
                repository
                    .set_state(name, ListenerStatus::Error, Some(error_text.as_str()))
                    .await?;
                warn!(listener = name, error = %error_text, "listener failed to start");
                Err(ListenerManagerError::StartFailed {
                    name: name.to_owned(),
                    message: error_text,
                })
            }
        }
    }

    pub(super) async fn stop_locked(
        &self,
        name: &str,
    ) -> Result<super::ListenerSummary, ListenerManagerError> {
        let repository = self.repository();

        if repository.get(name).await?.is_none() {
            return Err(ListenerManagerError::ListenerNotFound { name: name.to_owned() });
        }

        let Some(handle) = self.active_handles.write().await.remove(name) else {
            return Err(ListenerManagerError::ListenerNotRunning { name: name.to_owned() });
        };

        handle.abort();
        if let Err(error) = handle.await {
            if error.is_panic() {
                tracing::warn!(listener = name, "listener task panicked during stop: {error}");
            }
        }

        // Clean up external listener endpoint registry entries that won't get
        // deregistered inside the aborted future.
        self.external_endpoints.write().await.retain(|_, state| state.listener_name() != name);

        // Stop the cert file-watcher task if one was spawned for this listener.
        if let Some(watcher) = self.watcher_handles.write().await.remove(name) {
            watcher.abort();
            let _ = watcher.await;
        }

        // Remove the live TLS config handle so hot-reload calls are rejected after stop.
        self.tls_configs.write().await.remove(name);

        repository.set_state(name, ListenerStatus::Stopped, None).await?;
        info!(listener = name, "listener stopped");
        self.summary(name).await
    }

    async fn prune_finished_handle(&self, name: &str) {
        let should_remove = {
            let handles = self.active_handles.read().await;
            handles.get(name).is_some_and(JoinHandle::is_finished)
        };

        if should_remove {
            self.active_handles.write().await.remove(name);
        }
    }

    async fn spawn_listener_runtime(
        &self,
        config: &ListenerConfig,
    ) -> Result<JoinHandle<()>, ListenerManagerError> {
        let runtime = match config {
            ListenerConfig::Http(config) => {
                super::super::http::spawn_http_listener_runtime(
                    config,
                    self.agent_registry.clone(),
                    self.events.clone(),
                    self.database.clone(),
                    self.sockets.clone(),
                    self.plugins.clone(),
                    self.downloads.clone(),
                    self.demon_init_rate_limiter.clone(),
                    self.unknown_callback_probe_audit_limiter.clone(),
                    self.reconnect_probe_rate_limiter.clone(),
                    self.ecdh_registration_rate_limiter.clone(),
                    self.shutdown.clone(),
                    self.max_pivot_chain_depth,
                    self.init_secret_config(),
                    self.demon_allow_legacy_ctr,
                    self.tls_configs.clone(),
                    self.watcher_handles.clone(),
                    self.corpus_capture.clone(),
                )
                .await
            }
            ListenerConfig::Smb(config) => {
                super::super::smb::spawn_smb_listener_runtime(
                    config,
                    self.agent_registry.clone(),
                    self.events.clone(),
                    self.database.clone(),
                    self.sockets.clone(),
                    self.plugins.clone(),
                    self.downloads.clone(),
                    self.unknown_callback_probe_audit_limiter.clone(),
                    self.reconnect_probe_rate_limiter.clone(),
                    self.demon_init_rate_limiter.clone(),
                    self.shutdown.clone(),
                    self.init_secret_config(),
                    self.max_pivot_chain_depth,
                    self.demon_allow_legacy_ctr,
                )
                .await
            }
            ListenerConfig::Dns(config) => {
                super::super::dns::spawn_dns_listener_runtime(
                    config,
                    self.agent_registry.clone(),
                    self.events.clone(),
                    self.database.clone(),
                    self.sockets.clone(),
                    self.plugins.clone(),
                    self.downloads.clone(),
                    self.demon_init_rate_limiter.clone(),
                    self.unknown_callback_probe_audit_limiter.clone(),
                    self.reconnect_probe_rate_limiter.clone(),
                    self.shutdown.clone(),
                    self.init_secret_config(),
                    self.max_pivot_chain_depth,
                    self.demon_allow_legacy_ctr,
                )
                .await
            }
            ListenerConfig::External(config) => {
                super::super::external::spawn_external_listener_runtime(
                    config,
                    self.agent_registry.clone(),
                    self.events.clone(),
                    self.database.clone(),
                    self.sockets.clone(),
                    self.plugins.clone(),
                    self.downloads.clone(),
                    self.demon_init_rate_limiter.clone(),
                    self.unknown_callback_probe_audit_limiter.clone(),
                    self.reconnect_probe_rate_limiter.clone(),
                    self.shutdown.clone(),
                    self.external_endpoints.clone(),
                    self.init_secret_config(),
                    self.max_pivot_chain_depth,
                    self.demon_allow_legacy_ctr,
                )
            }
        }?;

        Ok(spawn_managed_listener_task(
            config.name().to_owned(),
            runtime,
            self.repository(),
            self.active_handles.clone(),
        ))
    }
}

/// Wrap a listener runtime future in a Tokio task and persist the terminal
/// state when it exits.
pub(crate) fn spawn_managed_listener_task(
    name: String,
    runtime: ListenerRuntimeFuture,
    repository: ListenerRepository,
    active_handles: Arc<RwLock<BTreeMap<String, JoinHandle<()>>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let outcome = runtime.await;
        active_handles.write().await.remove(&name);

        match outcome {
            Ok(()) => {
                if let Err(error) = repository.set_state(&name, ListenerStatus::Stopped, None).await
                {
                    warn!(
                        listener = %name,
                        %error,
                        "listener runtime exited but stopped state could not be persisted"
                    );
                } else {
                    info!(listener = %name, "listener runtime exited");
                }
            }
            Err(message) => {
                if let Err(error) =
                    repository.set_state(&name, ListenerStatus::Error, Some(message.as_str())).await
                {
                    warn!(
                        listener = %name,
                        runtime_error = %message,
                        %error,
                        "listener runtime failed and error state could not be persisted"
                    );
                } else {
                    warn!(listener = %name, error = %message, "listener runtime exited with error");
                }
            }
        }
    })
}
