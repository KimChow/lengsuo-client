use agent_core::{EventLog, JsonlEventLog};
use serde_json::json;
#[test]
fn maximum_read_limit_is_rejected_without_panicking() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("data"), "safe").unwrap();
    let result = agent_core::workspace_read::read_workspace_file(dir.path(), "data", usize::MAX);
    assert!(
        result.is_err(),
        "unrepresentable probe limit must fail closed"
    );
}
#[test]
fn rejected_first_oversized_record_leaves_no_session_index() {
    let dir = tempfile::tempdir().unwrap();
    let log = JsonlEventLog::open(dir.path()).unwrap();
    let id = uuid::Uuid::new_v4();
    assert!(log
        .append(
            id,
            "text",
            json!({"text":"x".repeat(agent_core::event_log::MAX_LINE_BYTES)})
        )
        .is_err());
    assert!(
        log.sessions().is_empty(),
        "failed first append must not publish an empty session"
    );
    assert_eq!(log.last_seq(id), None);
    assert!(log.replay(id, 0, 10).unwrap().is_empty());
    assert_eq!(log.append(id, "text", json!({"text":"ok"})).unwrap().seq, 1);
}
