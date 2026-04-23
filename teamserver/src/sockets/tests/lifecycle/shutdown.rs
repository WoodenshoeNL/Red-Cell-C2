use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::oneshot;

use super::super::super::{SocketRelayError, SocksServerHandle};

#[tokio::test]
async fn socks_server_handle_shutdown_signals_graceful_exit() {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let graceful_exit = Arc::new(AtomicBool::new(false));
    let graceful_exit_task = Arc::clone(&graceful_exit);
    let task = tokio::spawn(async move {
        tokio::select! {
            _ = shutdown_rx => graceful_exit_task.store(true, Ordering::SeqCst),
            _ = std::future::pending::<()>() => {}
        }
    });
    let mut handle = SocksServerHandle {
        local_addr: "127.0.0.1:0".to_owned(),
        shutdown: Some(shutdown_tx),
        task,
    };

    handle.shutdown();

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !handle.task.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown task should finish");
    assert!(graceful_exit.load(Ordering::SeqCst));
    assert!(handle.shutdown.is_none());
}

#[tokio::test]
async fn socks_server_handle_port_returns_error_for_invalid_local_addr() {
    let task = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });
    let handle =
        SocksServerHandle { local_addr: "invalid-address".to_owned(), shutdown: None, task };

    assert!(matches!(
        handle.port(),
        Err(SocketRelayError::InvalidLocalAddress { local_addr }) if local_addr == "invalid-address"
    ));
}
