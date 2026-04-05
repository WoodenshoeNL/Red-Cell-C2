use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures_util::SinkExt;
use red_cell_common::crypto::seal_ws_frame;
use red_cell_common::operator::OperatorMessage;
use tokio::sync::mpsc;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::protocol::Message as WebSocketMessage,
};

/// Serialise and send outgoing operator messages over the WebSocket write half.
///
/// Exits when the outgoing channel is closed (all senders dropped) or when a
/// WebSocket write error occurs.
pub(super) async fn run_send_loop(
    mut write: futures_util::stream::SplitSink<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>, WebSocketMessage>,
    outgoing_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<OperatorMessage>>>,
    hmac_key: Arc<tokio::sync::Mutex<Option<[u8; 32]>>>,
    send_seq: Arc<AtomicU64>,
) -> Result<(), String> {
    loop {
        let next_message = {
            let mut receiver = outgoing_rx.lock().await;
            receiver.recv().await
        };

        let Some(message) = next_message else {
            return Ok(());
        };

        let payload = serde_json::to_string(&message).map_err(|error| error.to_string())?;
        let key_snapshot = *hmac_key.lock().await;
        let wire = if let Some(key) = key_snapshot {
            let seq = send_seq.fetch_add(1, Ordering::Relaxed);
            let envelope = seal_ws_frame(&key, seq, &payload);
            serde_json::to_string(&envelope).map_err(|e| e.to_string())?
        } else {
            payload
        };
        write.send(WebSocketMessage::Text(wire.into())).await.map_err(|error| error.to_string())?;
    }
}
