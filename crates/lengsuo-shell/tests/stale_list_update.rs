//! `session_update` 事件的更旧时间戳保护（PC26 活跃时间只前进）。
//!
//! 覆盖：更旧事件必须报错且整行快照不变；相同时间保持既有可更新行为；
//! 合法新时间生效；终态不得被非终态复活。

use lengsuo_shell::state::{SessionListItem, SessionListState, SessionStatus, StateError};

fn item(id: &str, status: SessionStatus, updated_at_ms: u64) -> SessionListItem {
    SessionListItem {
        id: id.to_string(),
        title: format!("任务 {id}"),
        mode: "craft".to_string(),
        status,
        updated_at_ms,
        env_binding: Some("dev".to_string()),
    }
}

/// 活跃行停在 1000ms：更旧事件必须被拒绝，且 title/status/mode/env/time 全部不变。
#[test]
fn stale_update_is_rejected_and_snapshot_unchanged() {
    let mut state = SessionListState::new();
    state
        .upsert(item("s1", SessionStatus::Idle, 1_000))
        .expect("基线插入");
    let before = state.get("s1").expect("行存在").clone();

    let err = state
        .apply_update(
            "s1",
            Some(SessionStatus::Running),
            900,
            Some("plan"),
            Some(Some("prod")),
        )
        .expect_err("更旧时间戳必须报错");
    assert!(
        matches!(err, StateError::InvalidTransition { .. }),
        "应为 InvalidTransition，实际 {err:?}"
    );
    assert_eq!(state.get("s1").expect("行存在"), &before);
    assert_eq!(before.title, "任务 s1");
    assert_eq!(before.status, SessionStatus::Idle);
    assert_eq!(before.mode, "craft");
    assert_eq!(before.env_binding.as_deref(), Some("dev"));
    assert_eq!(before.updated_at_ms, 1_000);

    // 未知会话仍按 UnknownSession 报错，不与更旧时间戳混淆。
    let unknown = state.apply_update("nope", None, 2_000, None, None);
    assert_eq!(unknown, Err(StateError::UnknownSession("nope".to_string())));
}

/// 相同时间戳沿用既有可更新语义（与 `upsert` 一致：不严格更旧即放行）。
#[test]
fn same_timestamp_update_still_applies() {
    let mut state = SessionListState::new();
    state
        .upsert(item("s1", SessionStatus::Idle, 1_000))
        .expect("基线插入");

    state
        .apply_update("s1", Some(SessionStatus::Running), 1_000, None, None)
        .expect("相同时间戳应允许更新");
    assert_eq!(state.get("s1").unwrap().status, SessionStatus::Running);
    assert_eq!(state.get("s1").unwrap().updated_at_ms, 1_000);
}

/// 合法新时间正常生效，缺失字段保持原值；终态行不得被非终态复活。
#[test]
fn newer_update_applies_and_terminal_stays_sealed() {
    let mut state = SessionListState::new();
    state
        .upsert(item("s1", SessionStatus::Idle, 1_000))
        .expect("基线插入");

    state
        .apply_update("s1", Some(SessionStatus::Done), 2_000, None, None)
        .expect("合法新事件");
    assert_eq!(state.get("s1").unwrap().status, SessionStatus::Done);
    assert_eq!(state.get("s1").unwrap().updated_at_ms, 2_000);
    assert_eq!(state.get("s1").unwrap().mode, "craft");

    let err = state
        .apply_update("s1", Some(SessionStatus::Running), 3_000, None, None)
        .expect_err("终态不得复活");
    assert_eq!(err, StateError::Sealed("s1".to_string()));

    // 终态之后的更旧事件仍按终态优先报错，快照仍不变。
    let err = state
        .apply_update("s1", Some(SessionStatus::Idle), 500, None, None)
        .expect_err("终态不得复活");
    assert_eq!(err, StateError::Sealed("s1".to_string()));
    assert_eq!(state.get("s1").unwrap().updated_at_ms, 2_000);
}

/// `upsert` 的既有回退保护不受影响。
#[test]
fn upsert_rejects_older_timestamp() {
    let mut state = SessionListState::new();
    state
        .upsert(item("s1", SessionStatus::Idle, 1_000))
        .expect("基线插入");

    let err = state
        .upsert(item("s1", SessionStatus::Running, 100))
        .expect_err("更旧 upsert 必须报错");
    assert!(matches!(err, StateError::InvalidTransition { .. }));
    assert_eq!(state.get("s1").unwrap().updated_at_ms, 1_000);
}
