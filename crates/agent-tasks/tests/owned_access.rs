//! 会话作用域访问门（1.47 微卡）：`get_for_session` / `update_status_for_session`。
//!
//! 行为来源：PC05 的 TaskGet/Update 按会话隔离读取与更新（只读参考行为，不搬代码/提示词）；
//! 隔离层级沿用我方「用户/租户/环境/会话」中的会话一层。
//! 契约：owner 不匹配与任务不存在一律返回现有 `TaskError::NotFound`（同形错误，不泄露
//! 任务存在性与内容），且拒绝路径不修改状态、不刷新 `updated_at_ms`；匹配时复用原 `get`/
//! `update_status`，状态机与幂等语义不变。

mod support;

use crate::support::{frozen_board, FROZEN_MS};
use agent_tasks::{TaskBoard, TaskError, TaskStatus};
use uuid::Uuid;

fn owner_session() -> Uuid {
    Uuid::from_u128(0x_0a0a_0a0a_0a0a_0a0a_0a0a_0a0a_0a0a)
}

fn intruder_session() -> Uuid {
    Uuid::from_u128(0x_0b0b_0b0b_0b0b_0b0b_0b0b_0b0b_0b0b)
}

// ---- 读取门 ----

#[test]
fn get_for_session_returns_task_when_session_matches() {
    let mut b = frozen_board();
    let t = b.create(owner_session(), "会话门", "描述A").unwrap();

    let got = b.get_for_session(owner_session(), t.id).unwrap();
    assert_eq!(got.id, t.id);
    assert_eq!(got.subject, "会话门");
    assert_eq!(got.description, "描述A");
    assert_eq!(got.status, TaskStatus::Pending);
}

#[test]
fn get_for_session_other_session_is_indistinguishable_not_found() {
    let mut b = frozen_board();
    let t = b.create(owner_session(), "会话门", "私密描述").unwrap();

    let err = b.get_for_session(intruder_session(), t.id).unwrap_err();
    // 与「不存在」完全同形：错误类型不带任务信息，不泄露任务是否真实存在。
    assert_eq!(err, TaskError::NotFound);
    assert_eq!(err.to_string(), TaskError::NotFound.to_string());
}

#[test]
fn get_for_session_unknown_task_is_not_found() {
    let b = frozen_board();
    let err = b
        .get_for_session(owner_session(), Uuid::new_v4())
        .unwrap_err();
    assert_eq!(err, TaskError::NotFound);
}

#[test]
fn to_json_for_session_shape_via_read_gate() {
    // 读取门返回同一 Task 引用语义（复用 get），JSON 契约字段不变。
    let mut b = frozen_board();
    let t = b.create(owner_session(), "会话门", "描述A").unwrap();
    let got = b.get_for_session(owner_session(), t.id).unwrap();
    let value = serde_json::to_value(got).unwrap();
    assert_eq!(value["id"], serde_json::json!(t.id.to_string()));
    assert_eq!(value["status"], serde_json::json!("pending"));
    assert_eq!(
        value["session_id"],
        serde_json::json!(owner_session().to_string())
    );
}

// ---- 更新门 ----

#[test]
fn update_status_for_session_transitions_when_session_matches() {
    let mut b = frozen_board();
    let t = b.create(owner_session(), "会话门", "描述A").unwrap();

    let updated = b
        .update_status_for_session(owner_session(), t.id, TaskStatus::InProgress)
        .unwrap();
    assert_eq!(updated.status, TaskStatus::InProgress);
    assert_eq!(b.get(t.id).unwrap().status, TaskStatus::InProgress);
}

#[test]
fn update_status_for_session_other_session_leaves_status_and_time_untouched() {
    let mut b = frozen_board();
    let t = b.create(owner_session(), "会话门", "描述A").unwrap();

    let err = b
        .update_status_for_session(intruder_session(), t.id, TaskStatus::InProgress)
        .unwrap_err();
    assert_eq!(err, TaskError::NotFound);

    let after = b.get(t.id).unwrap();
    assert_eq!(after.status, TaskStatus::Pending, "越权请求不得改状态");
    assert_eq!(after.updated_at_ms, FROZEN_MS, "越权请求不得刷新更新时间");
    assert_eq!(after.created_at_ms, FROZEN_MS);
    assert_eq!(after.subject, "会话门");
    assert_eq!(after.description, "描述A");
}

#[test]
fn update_status_for_session_unknown_task_mutates_nothing() {
    let mut b = frozen_board();
    let t = b.create(owner_session(), "保留任务", "描述A").unwrap();
    let other = Uuid::new_v4();

    let err = b
        .update_status_for_session(owner_session(), other, TaskStatus::Done)
        .unwrap_err();
    assert_eq!(err, TaskError::NotFound);

    let after = b.get(t.id).unwrap();
    assert_eq!(after.status, TaskStatus::Pending);
    assert_eq!(after.updated_at_ms, FROZEN_MS);
    assert_eq!(b.list_by_session(owner_session()).len(), 1);
}

#[test]
fn update_status_for_session_terminal_target_is_not_found_not_transition() {
    // 越权者请求把别人任务打到终态：仍只报 NotFound，不暴露当前状态机信息。
    let mut b = frozen_board();
    let t = b.create(owner_session(), "进行中的任务", "描述A").unwrap();
    support::park(&mut b, t.id, TaskStatus::InProgress);

    let err = b
        .update_status_for_session(intruder_session(), t.id, TaskStatus::Done)
        .unwrap_err();
    assert_eq!(err, TaskError::NotFound);
    assert_eq!(b.get(t.id).unwrap().status, TaskStatus::InProgress);
}

#[test]
fn update_status_for_session_owner_keeps_state_machine_enforced() {
    let mut b = TaskBoard::with_clock(support::ticking_clock());
    let t = b.create(owner_session(), "会话门", "描述A").unwrap();
    b.update_status_for_session(owner_session(), t.id, TaskStatus::InProgress)
        .unwrap();
    b.update_status_for_session(owner_session(), t.id, TaskStatus::Done)
        .unwrap();

    let err = b
        .update_status_for_session(owner_session(), t.id, TaskStatus::InProgress)
        .unwrap_err();
    assert!(
        matches!(err, TaskError::InvalidTransition { .. }),
        "合法 owner 仍受状态机约束，got {err:?}"
    );
}

#[test]
fn update_status_for_session_owner_same_status_is_idempotent() {
    let mut b = TaskBoard::with_clock(support::ticking_clock());
    let t = b.create(owner_session(), "会话门", "描述A").unwrap();
    let before = b.get(t.id).unwrap().updated_at_ms;

    let again = b
        .update_status_for_session(owner_session(), t.id, TaskStatus::Pending)
        .unwrap();
    assert_eq!(again.status, TaskStatus::Pending);
    assert_eq!(again.updated_at_ms, before, "幂等请求不应刷新时间");
}

// ---- 兼容与索引 ----

#[test]
fn list_by_session_only_exposes_own_session_tasks() {
    let mut b = frozen_board();
    let mine = b.create(owner_session(), "我的", "A").unwrap();
    let theirs = b.create(intruder_session(), "别人的", "B").unwrap();

    let ids: Vec<Uuid> = b
        .list_by_session(owner_session())
        .iter()
        .map(|t| t.id)
        .collect();
    assert_eq!(ids, vec![mine.id]);
    // 越权读取被拒，但目标任务仍在看板上（本卡不做删除）。
    assert_eq!(b.get(theirs.id).unwrap().subject, "别人的");
}

#[test]
fn legacy_get_and_update_status_still_work() {
    // 旧 API 保持兼容（作为底层宿主内部 API）：仅新增方法，语义未变。
    let mut b = frozen_board();
    let t = b.create(owner_session(), "旧 API", "A").unwrap();
    assert!(b.get(t.id).is_ok());
    assert!(b.update_status(t.id, TaskStatus::InProgress).is_ok());
    assert!(b.get(Uuid::new_v4()).is_err());
}
