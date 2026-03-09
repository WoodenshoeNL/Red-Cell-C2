//! Operator event broadcasting infrastructure.

use red_cell_common::operator::OperatorMessage;
use tokio::sync::broadcast;
use tracing::warn;

const DEFAULT_EVENT_BUS_CAPACITY: usize = 256;

/// Fan-out broadcaster for operator WebSocket events.
#[derive(Clone, Debug)]
pub struct EventBus {
    sender: broadcast::Sender<OperatorMessage>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(DEFAULT_EVENT_BUS_CAPACITY)
    }
}

impl EventBus {
    /// Create a new event bus with the given ring-buffer capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Subscribe to future operator events.
    #[must_use]
    pub fn subscribe(&self) -> EventReceiver {
        EventReceiver { receiver: Some(self.sender.subscribe()) }
    }

    /// Broadcast an event to all currently connected operators.
    ///
    /// Returns the number of active subscribers that received the event.
    pub fn broadcast(&self, event: OperatorMessage) -> usize {
        self.sender.send(event).unwrap_or_default()
    }
}

/// Handle for receiving broadcast operator events.
#[derive(Debug)]
pub struct EventReceiver {
    receiver: Option<broadcast::Receiver<OperatorMessage>>,
}

impl EventReceiver {
    /// Receive the next event, dropping the subscription if it lagged or disconnected.
    pub async fn recv(&mut self) -> Option<OperatorMessage> {
        let receiver = self.receiver.as_mut()?;

        match receiver.recv().await {
            Ok(event) => Some(event),
            Err(broadcast::error::RecvError::Closed) => {
                self.receiver = None;
                None
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(skipped, "dropping lagging operator event subscription");
                self.receiver = None;
                None
            }
        }
    }

    /// Returns `true` once the subscription has been closed or dropped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.receiver.is_none()
    }
}

#[cfg(test)]
mod tests {
    use red_cell_common::operator::{
        EventCode, Message, MessageHead, OperatorMessage, TeamserverLogInfo,
    };

    use super::EventBus;

    fn log_message(text: &str) -> OperatorMessage {
        OperatorMessage::TeamserverLog(Message {
            head: MessageHead {
                event: EventCode::Teamserver,
                user: "operator".to_owned(),
                timestamp: "12:34:56".to_owned(),
                one_time: String::new(),
            },
            info: TeamserverLogInfo { text: text.to_owned() },
        })
    }

    #[tokio::test]
    async fn broadcast_delivers_events_to_all_subscribers() {
        let bus = EventBus::new(8);
        let mut first = bus.subscribe();
        let mut second = bus.subscribe();
        let event = log_message("hello");

        assert_eq!(bus.broadcast(event.clone()), 2);
        assert_eq!(first.recv().await, Some(event.clone()));
        assert_eq!(second.recv().await, Some(event));
    }

    #[tokio::test]
    async fn broadcast_ignores_disconnected_subscribers() {
        let bus = EventBus::new(8);
        let first = bus.subscribe();
        let second = bus.subscribe();

        drop(first);
        drop(second);

        assert_eq!(bus.broadcast(log_message("nobody")), 0);
    }

    #[tokio::test]
    async fn lagging_subscriptions_are_dropped() {
        let bus = EventBus::new(2);
        let mut receiver = bus.subscribe();

        assert_eq!(bus.broadcast(log_message("one")), 1);
        assert_eq!(bus.broadcast(log_message("two")), 1);
        assert_eq!(bus.broadcast(log_message("three")), 1);

        assert_eq!(receiver.recv().await, None);
        assert!(receiver.is_closed());
        assert_eq!(receiver.recv().await, None);
    }
}
