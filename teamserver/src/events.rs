//! Operator event broadcasting infrastructure.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use red_cell_common::operator::{
    EventCode, Message, MessageHead, OperatorMessage, TeamserverLogInfo,
};
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tracing::{trace, warn};

const DEFAULT_EVENT_BUS_CAPACITY: usize = 256;

/// Builds a [`OperatorMessage::TeamserverLog`] retained for `/debug/server-logs` and operator consoles.
#[must_use]
pub(crate) fn teamserver_log_operator_message(user: &str, text: &str) -> OperatorMessage {
    OperatorMessage::TeamserverLog(Message {
        head: MessageHead {
            event: EventCode::Teamserver,
            user: user.to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: TeamserverLogInfo { text: text.to_owned() },
    })
}

/// Broadcasts a retained teamserver log line (ring buffer + live WebSocket subscribers).
pub(crate) fn broadcast_teamserver_line(events: &EventBus, user: &str, text: &str) -> usize {
    events.broadcast(teamserver_log_operator_message(user, text))
}

/// Fan-out broadcaster for operator WebSocket events.
#[derive(Clone, Debug)]
pub struct EventBus {
    sender: broadcast::Sender<OperatorMessage>,
    recent_teamserver_logs: Arc<Mutex<VecDeque<OperatorMessage>>>,
    history_capacity: usize,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(DEFAULT_EVENT_BUS_CAPACITY)
    }
}

impl EventBus {
    /// Create a new event bus with the given ring-buffer capacity.
    ///
    /// A `capacity` of `0` disables retained teamserver log history.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let channel_capacity = capacity.max(1);
        let (sender, _) = broadcast::channel(channel_capacity);
        Self {
            sender,
            recent_teamserver_logs: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            history_capacity: capacity,
        }
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
        if matches!(event, OperatorMessage::TeamserverLog(_)) {
            let mut history = match self.recent_teamserver_logs.lock() {
                Ok(history) => history,
                Err(poisoned) => {
                    warn!("teamserver log history mutex poisoned — recovering");
                    poisoned.into_inner()
                }
            };
            if self.history_capacity == 0 {
                return match self.sender.send(event) {
                    Ok(n) => n,
                    Err(_) => {
                        trace!("event broadcast dropped — no active subscribers");
                        0
                    }
                };
            }
            if history.len() == self.history_capacity {
                history.pop_front();
            }
            history.push_back(event.clone());
        }

        match self.sender.send(event) {
            Ok(n) => n,
            Err(_) => {
                trace!("event broadcast dropped — no active subscribers");
                0
            }
        }
    }

    /// Return the retained recent teamserver log messages in original order.
    pub fn recent_teamserver_logs(&self) -> Vec<OperatorMessage> {
        match self.recent_teamserver_logs.lock() {
            Ok(history) => history.iter().cloned().collect(),
            Err(poisoned) => {
                warn!("teamserver log history mutex poisoned — recovering");
                poisoned.into_inner().iter().cloned().collect()
            }
        }
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
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use red_cell_common::operator::{
        ChatUserInfo, EventCode, FlatInfo, ListenerErrorInfo, Message, MessageHead,
        OperatorMessage, TeamserverLogInfo,
    };

    use super::{EventBus, broadcast_teamserver_line, teamserver_log_operator_message};

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
    async fn new_subscription_is_not_closed() {
        let bus = EventBus::new(8);
        let receiver = bus.subscribe();

        assert!(!receiver.is_closed());
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

    #[tokio::test]
    async fn closed_bus_causes_recv_to_return_none() {
        let bus = EventBus::new(8);
        let mut receiver = bus.subscribe();

        drop(bus);

        assert_eq!(receiver.recv().await, None);
        assert!(receiver.is_closed());
        // A second call must also return None immediately without blocking.
        assert_eq!(receiver.recv().await, None);
    }

    #[tokio::test]
    async fn recent_teamserver_logs_retain_only_log_events() {
        let bus = EventBus::new(2);
        let first = log_message("one");
        let second = log_message("two");
        let third = log_message("three");

        assert_eq!(bus.broadcast(first), 0);
        assert_eq!(
            bus.broadcast(OperatorMessage::InitConnectionSuccess(Message {
                head: MessageHead {
                    event: EventCode::InitConnection,
                    user: "operator".to_owned(),
                    timestamp: String::new(),
                    one_time: String::new(),
                },
                info: red_cell_common::operator::MessageInfo { message: "ok".to_owned() },
            })),
            0
        );
        assert_eq!(bus.broadcast(second.clone()), 0);
        assert_eq!(bus.broadcast(third.clone()), 0);

        assert_eq!(bus.recent_teamserver_logs(), vec![second, third]);
    }

    #[tokio::test]
    async fn non_log_variants_are_delivered_but_not_retained() {
        let bus = EventBus::new(8);
        let mut receiver = bus.subscribe();

        let head = |event| MessageHead {
            event,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        };

        let non_log_events: Vec<OperatorMessage> = vec![
            OperatorMessage::ChatMessage(Message {
                head: head(EventCode::Chat),
                info: FlatInfo { fields: BTreeMap::new() },
            }),
            OperatorMessage::ListenerError(Message {
                head: head(EventCode::Listener),
                info: ListenerErrorInfo {
                    error: "bind failed".to_owned(),
                    name: "http".to_owned(),
                },
            }),
            OperatorMessage::ChatUserConnected(Message {
                head: head(EventCode::Chat),
                info: ChatUserInfo { user: "alice".to_owned() },
            }),
            OperatorMessage::AgentRemove(Message {
                head: head(EventCode::Session),
                info: FlatInfo { fields: BTreeMap::new() },
            }),
        ];

        for event in &non_log_events {
            let count = bus.broadcast(event.clone());
            assert_eq!(count, 1, "each broadcast should reach the single subscriber");
        }

        // Verify all events were delivered to the subscriber.
        for expected in &non_log_events {
            let received = receiver.recv().await;
            assert_eq!(received.as_ref(), Some(expected));
        }

        // History must remain empty — none of these are TeamserverLog.
        assert!(
            bus.recent_teamserver_logs().is_empty(),
            "non-log variants must not appear in teamserver log history"
        );
    }

    #[tokio::test]
    async fn zero_capacity_history_does_not_retain_logs() {
        let bus = EventBus::new(0);

        assert_eq!(bus.broadcast(log_message("discarded")), 0);
        assert!(bus.recent_teamserver_logs().is_empty());
    }

    #[tokio::test]
    async fn capacity_one_evicts_on_second_log() {
        let bus = EventBus::new(1);
        let first = log_message("first");
        let second = log_message("second");

        bus.broadcast(first);
        bus.broadcast(second.clone());

        let logs = bus.recent_teamserver_logs();
        assert_eq!(logs, vec![second]);
    }

    /// Poison the inner history mutex by panicking a thread while it holds the lock.
    fn poison_history(bus: &EventBus) {
        let mutex = Arc::clone(&bus.recent_teamserver_logs);
        let handle = std::thread::spawn(move || {
            let _guard = mutex.lock().expect("unwrap");
            panic!("intentional panic to poison mutex");
        });
        // The thread panicked — join returns Err but the mutex is now poisoned.
        let _ = handle.join();
    }

    #[tokio::test]
    async fn broadcast_recovers_from_poisoned_history_mutex() {
        let bus = EventBus::new(4);

        // Broadcast one event before poisoning so the history is non-empty.
        bus.broadcast(log_message("before-poison"));

        poison_history(&bus);

        // broadcast() should recover via poisoned.into_inner() rather than panicking.
        let count = bus.broadcast(log_message("after-poison"));
        // No subscribers, so count is 0 — the important thing is we didn't panic.
        assert_eq!(count, 0);

        // The history should contain both messages, proving the poisoned guard was recovered.
        let logs = bus.recent_teamserver_logs();
        assert_eq!(logs, vec![log_message("before-poison"), log_message("after-poison")]);
    }

    #[tokio::test]
    async fn recent_teamserver_logs_recovers_from_poisoned_mutex() {
        let bus = EventBus::new(4);

        bus.broadcast(log_message("surviving"));

        poison_history(&bus);

        // recent_teamserver_logs() should recover rather than panicking.
        let logs = bus.recent_teamserver_logs();
        assert_eq!(logs, vec![log_message("surviving")]);
    }

    #[tokio::test]
    async fn broadcast_and_logs_work_after_repeated_poisoning() {
        let bus = EventBus::new(4);

        bus.broadcast(log_message("first"));
        poison_history(&bus);

        bus.broadcast(log_message("second"));
        poison_history(&bus);

        bus.broadcast(log_message("third"));

        let logs = bus.recent_teamserver_logs();
        assert_eq!(logs, vec![log_message("first"), log_message("second"), log_message("third")]);
    }

    #[tokio::test]
    async fn clone_shares_recent_teamserver_logs() {
        let bus = EventBus::new(4);
        let clone = bus.clone();

        // Broadcasting on the clone should appear in the original's history.
        clone.broadcast(log_message("from-clone"));

        let logs = bus.recent_teamserver_logs();
        assert_eq!(logs, vec![log_message("from-clone")]);

        // Broadcasting on the original should appear in the clone's history.
        bus.broadcast(log_message("from-original"));

        let logs = clone.recent_teamserver_logs();
        assert_eq!(logs, vec![log_message("from-clone"), log_message("from-original")]);
    }

    #[tokio::test]
    async fn clone_subscribers_receive_broadcasts_from_original() {
        let bus = EventBus::new(4);
        let clone = bus.clone();

        let mut sub_on_original = bus.subscribe();
        let mut sub_on_clone = clone.subscribe();

        // Broadcast on the original — both subscribers should receive it.
        bus.broadcast(log_message("from-original"));
        assert_eq!(sub_on_original.recv().await, Some(log_message("from-original")));
        assert_eq!(sub_on_clone.recv().await, Some(log_message("from-original")));

        // Broadcast on the clone — both subscribers should receive it.
        clone.broadcast(log_message("from-clone"));
        assert_eq!(sub_on_original.recv().await, Some(log_message("from-clone")));
        assert_eq!(sub_on_clone.recv().await, Some(log_message("from-clone")));
    }

    #[tokio::test]
    async fn clone_and_original_share_subscriber_count() {
        let bus = EventBus::new(4);
        let clone = bus.clone();

        let _sub = bus.subscribe();

        // Broadcasting from either side should see the same subscriber.
        assert_eq!(bus.broadcast(log_message("a")), 1);
        assert_eq!(clone.broadcast(log_message("b")), 1);
    }

    #[tokio::test]
    async fn wraparound_preserves_chronological_order() {
        let bus = EventBus::new(3);

        for i in 1..=5 {
            bus.broadcast(log_message(&format!("msg-{i}")));
        }

        let logs = bus.recent_teamserver_logs();
        assert_eq!(logs, vec![log_message("msg-3"), log_message("msg-4"), log_message("msg-5"),]);
    }

    #[test]
    fn broadcast_teamserver_line_retains_operator_visible_entry() {
        let bus = EventBus::new(8);
        let subscribers = broadcast_teamserver_line(&bus, "teamserver", "callback dispatch failed");
        assert_eq!(subscribers, 0);

        let logs = bus.recent_teamserver_logs();
        assert_eq!(logs.len(), 1);
        match &logs[0] {
            OperatorMessage::TeamserverLog(m) => {
                assert_eq!(m.head.user, "teamserver");
                assert_eq!(m.info.text, "callback dispatch failed");
            }
            other => panic!("expected TeamserverLog, got {other:?}"),
        }
    }

    #[test]
    fn teamserver_log_operator_message_matches_broadcast_shape() {
        let msg = teamserver_log_operator_message("alice", "hello");
        match msg {
            OperatorMessage::TeamserverLog(m) => {
                assert_eq!(m.head.user, "alice");
                assert_eq!(m.info.text, "hello");
            }
            other => panic!("expected TeamserverLog, got {other:?}"),
        }
    }
}
