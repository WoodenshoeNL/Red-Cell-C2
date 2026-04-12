use super::super::*;

#[test]
fn event_log_new_is_empty() {
    let log = EventLog::new(5);
    assert_eq!(log.len(), 0);
    assert_eq!(log.unread_count, 0);
    assert!(log.entries.is_empty());
}

#[test]
fn event_log_push_increments_len_and_unread() {
    let mut log = EventLog::new(3);
    log.push(EventKind::Agent, "alice", "t1", "msg1");
    assert_eq!(log.len(), 1);
    assert_eq!(log.unread_count, 1);

    log.push(EventKind::System, "server", "t2", "msg2");
    assert_eq!(log.len(), 2);
    assert_eq!(log.unread_count, 2);
}

#[test]
fn event_log_push_evicts_oldest_when_at_capacity() {
    let mut log = EventLog::new(3);
    log.push(EventKind::Agent, "a", "t1", "first");
    log.push(EventKind::System, "b", "t2", "second");
    log.push(EventKind::Operator, "c", "t3", "third");
    assert_eq!(log.len(), 3);
    assert_eq!(log.unread_count, 3);

    // 4th push should evict "first"
    log.push(EventKind::Agent, "d", "t4", "fourth");
    assert_eq!(log.len(), 3);
    // evicted entry was unread, so unread_count = 3 - 1 + 1 = 3
    assert_eq!(log.unread_count, 3);

    // Verify "first" is gone and "second" is now the oldest
    assert_eq!(log.entries.front().unwrap().message, "second");
    assert_eq!(log.entries.back().unwrap().message, "fourth");
}

#[test]
fn event_log_eviction_of_read_entry_does_not_decrement_unread() {
    let mut log = EventLog::new(2);
    log.push(EventKind::Agent, "a", "t1", "old");
    log.mark_all_read();
    assert_eq!(log.unread_count, 0);

    log.push(EventKind::Agent, "b", "t2", "new");
    assert_eq!(log.unread_count, 1);
    assert_eq!(log.len(), 2);

    // Evicts "old" which is read — unread_count should not be decremented
    log.push(EventKind::Agent, "c", "t3", "newest");
    assert_eq!(log.len(), 2);
    // 1 (prior unread) + 1 (new push) - 0 (evicted was read) = 2
    assert_eq!(log.unread_count, 2);
}

#[test]
fn event_log_eviction_of_unread_entry_decrements_unread() {
    let mut log = EventLog::new(2);
    log.push(EventKind::Agent, "a", "t1", "old-unread");
    log.push(EventKind::System, "b", "t2", "newer");
    assert_eq!(log.unread_count, 2);

    // Evicts "old-unread" which is unread
    log.push(EventKind::Operator, "c", "t3", "newest");
    assert_eq!(log.len(), 2);
    // 2 - 1 (evicted unread) + 1 (new push) = 2
    assert_eq!(log.unread_count, 2);
}

#[test]
fn event_log_mark_all_read_zeroes_unread_and_flags_entries() {
    let mut log = EventLog::new(5);
    log.push(EventKind::Agent, "a", "t1", "m1");
    log.push(EventKind::System, "b", "t2", "m2");
    log.push(EventKind::Operator, "c", "t3", "m3");
    assert_eq!(log.unread_count, 3);

    log.mark_all_read();
    assert_eq!(log.unread_count, 0);
    for entry in &log.entries {
        assert!(entry.read, "entry {:?} should be marked read", entry.message);
    }
}

#[test]
fn event_log_mark_all_read_is_idempotent() {
    let mut log = EventLog::new(5);
    log.push(EventKind::Agent, "a", "t1", "m1");
    log.mark_all_read();
    log.mark_all_read();
    assert_eq!(log.unread_count, 0);
}

#[test]
fn event_log_unread_by_kind_filters_correctly() {
    let mut log = EventLog::new(10);
    log.push(EventKind::Agent, "a", "t1", "agent1");
    log.push(EventKind::Agent, "a", "t2", "agent2");
    log.push(EventKind::System, "s", "t3", "sys1");
    log.push(EventKind::Operator, "o", "t4", "op1");
    log.push(EventKind::System, "s", "t5", "sys2");

    assert_eq!(log.unread_by_kind(EventKind::Agent), 2);
    assert_eq!(log.unread_by_kind(EventKind::System), 2);
    assert_eq!(log.unread_by_kind(EventKind::Operator), 1);
}

#[test]
fn event_log_unread_by_kind_excludes_read_entries() {
    let mut log = EventLog::new(10);
    log.push(EventKind::Agent, "a", "t1", "agent1");
    log.push(EventKind::System, "s", "t2", "sys1");
    log.mark_all_read();
    log.push(EventKind::Agent, "a", "t3", "agent2");

    assert_eq!(log.unread_by_kind(EventKind::Agent), 1);
    assert_eq!(log.unread_by_kind(EventKind::System), 0);
}

#[test]
fn event_log_unread_by_kind_returns_zero_when_empty() {
    let log = EventLog::new(5);
    assert_eq!(log.unread_by_kind(EventKind::Agent), 0);
    assert_eq!(log.unread_by_kind(EventKind::System), 0);
    assert_eq!(log.unread_by_kind(EventKind::Operator), 0);
}

#[test]
fn event_log_len_reflects_entries_after_eviction() {
    let mut log = EventLog::new(2);
    log.push(EventKind::Agent, "a", "t1", "m1");
    log.push(EventKind::Agent, "a", "t2", "m2");
    assert_eq!(log.len(), 2);

    log.push(EventKind::Agent, "a", "t3", "m3");
    assert_eq!(log.len(), 2);
}

#[test]
fn event_log_max_size_one() {
    let mut log = EventLog::new(1);
    log.push(EventKind::Agent, "a", "t1", "first");
    assert_eq!(log.len(), 1);
    assert_eq!(log.unread_count, 1);

    log.push(EventKind::System, "b", "t2", "second");
    assert_eq!(log.len(), 1);
    assert_eq!(log.unread_count, 1);
    assert_eq!(log.entries.front().unwrap().message, "second");
}

#[test]
fn event_log_push_stores_correct_fields() {
    let mut log = EventLog::new(5);
    log.push(EventKind::Operator, "alice", "2026-03-18T12:00:00", "hello world");

    let entry = log.entries.front().unwrap();
    assert_eq!(entry.kind, EventKind::Operator);
    assert_eq!(entry.author, "alice");
    assert_eq!(entry.sent_at, "2026-03-18T12:00:00");
    assert_eq!(entry.message, "hello world");
    assert!(!entry.read);
}

#[test]
fn event_log_full_scenario_push_evict_read_unread_by_kind() {
    // Integration-style test combining all operations
    let mut log = EventLog::new(3);

    // Fill to capacity
    log.push(EventKind::Agent, "a", "t1", "a1");
    log.push(EventKind::System, "s", "t2", "s1");
    log.push(EventKind::Agent, "a", "t3", "a2");
    assert_eq!(log.len(), 3);
    assert_eq!(log.unread_count, 3);
    assert_eq!(log.unread_by_kind(EventKind::Agent), 2);
    assert_eq!(log.unread_by_kind(EventKind::System), 1);

    // Push a 4th — evicts "a1" (unread Agent)
    log.push(EventKind::Operator, "o", "t4", "o1");
    assert_eq!(log.len(), 3);
    assert_eq!(log.unread_count, 3);
    assert_eq!(log.unread_by_kind(EventKind::Agent), 1);
    assert_eq!(log.unread_by_kind(EventKind::System), 1);
    assert_eq!(log.unread_by_kind(EventKind::Operator), 1);

    // Mark all read
    log.mark_all_read();
    assert_eq!(log.unread_count, 0);
    assert_eq!(log.unread_by_kind(EventKind::Agent), 0);

    // Push after mark_all_read — only new entry is unread
    log.push(EventKind::System, "s", "t5", "s2");
    assert_eq!(log.len(), 3);
    // Evicted "s1" which was read — no unread decrement
    assert_eq!(log.unread_count, 1);
    assert_eq!(log.unread_by_kind(EventKind::System), 1);
}
