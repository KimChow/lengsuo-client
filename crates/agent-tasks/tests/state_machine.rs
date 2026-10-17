//! 状态机测试：全迁移矩阵（合法 3 条 + 同状态幂等 + 非法若干）、终态、时间戳刷新。

mod support;

use agent_tasks::TaskStatus;
use support::{board, create, frozen_board, is_invalid_transition, park};

/// 合法迁移恰为三条：Pending→InProgress、InProgress→Done、InProgress→Cancelled。
const LEGAL: [(TaskStatus, TaskStatus); 3] = [
    (TaskStatus::Pending, TaskStatus::InProgress),
    (TaskStatus::InProgress, TaskStatus::Done),
    (TaskStatus::InProgress, TaskStatus::Cancelled),
];

#[test]
fn legal_transitions_are_accepted() {
    let mut b = board();
    let t = create(&mut b, "A");
    let moved = b
        .update_status(t.id, TaskStatus::InProgress)
        .expect("pending->in_progress");
    assert_eq!(moved.status, TaskStatus::InProgress);
    assert_eq!(moved.id, t.id, "id 不变");
    assert_eq!(moved.session_id, t.session_id, "session_id 不变");
    assert_eq!(moved.subject, t.subject, "改状态不动文本");

    let mut b2 = board();
    let t2 = create(&mut b2, "B");
    park(&mut b2, t2.id, TaskStatus::Done);
    assert_eq!(b2.get(t2.id).unwrap().status, TaskStatus::Done);

    let mut b3 = board();
    let t3 = create(&mut b3, "C");
    park(&mut b3, t3.id, TaskStatus::Cancelled);
    assert_eq!(b3.get(t3.id).unwrap().status, TaskStatus::Cancelled);
}

#[test]
fn transition_matrix_covers_every_pair() {
    // 4×4 = 16 组逐对验证：同状态幂等成功；3 组合法；其余 9 组非法。
    let mut legal_hits = 0usize;
    let mut illegal_hits = 0usize;
    let mut idempotent_hits = 0usize;
    for from in TaskStatus::ALL {
        for to in TaskStatus::ALL {
            let mut b = board();
            let t = create(&mut b, "M");
            park(&mut b, t.id, from);
            let result = b.update_status(t.id, to);
            if from == to {
                let task = result.unwrap_or_else(|e| panic!("{from:?}->{to:?} 应幂等，实为 {e:?}"));
                assert_eq!(task.status, from);
                idempotent_hits += 1;
            } else if LEGAL.contains(&(from, to)) {
                let task = result.unwrap_or_else(|e| panic!("{from:?}->{to:?} 应合法，实为 {e:?}"));
                assert_eq!(task.status, to);
                legal_hits += 1;
            } else {
                let err = result.expect_err("该迁移应非法");
                assert!(
                    is_invalid_transition(&err, from, to),
                    "错误变体不符: {err:?}"
                );
                assert_eq!(b.get(t.id).unwrap().status, from, "非法迁移不得改状态");
                illegal_hits += 1;
            }
        }
    }
    assert_eq!(legal_hits, 3, "合法迁移恰好 3 条");
    assert_eq!(idempotent_hits, 4, "同状态 4 组全部幂等");
    assert_eq!(illegal_hits, 9, "其余 9 组非法");
}

#[test]
fn terminal_states_are_final() {
    let mut b = board();
    let done = create(&mut b, "T");
    park(&mut b, done.id, TaskStatus::Done);
    for to in [
        TaskStatus::Pending,
        TaskStatus::InProgress,
        TaskStatus::Cancelled,
    ] {
        let err = b.update_status(done.id, to).unwrap_err();
        assert!(is_invalid_transition(&err, TaskStatus::Done, to));
    }

    let mut b2 = board();
    let cancelled = create(&mut b2, "C");
    park(&mut b2, cancelled.id, TaskStatus::Cancelled);
    for to in [
        TaskStatus::Pending,
        TaskStatus::InProgress,
        TaskStatus::Done,
    ] {
        let err = b2.update_status(cancelled.id, to).unwrap_err();
        assert!(is_invalid_transition(&err, TaskStatus::Cancelled, to));
    }
}

#[test]
fn cannot_skip_in_progress() {
    let mut b = board();
    let t = create(&mut b, "Skip");
    for to in [TaskStatus::Done, TaskStatus::Cancelled] {
        let err = b.update_status(t.id, to).unwrap_err();
        assert!(is_invalid_transition(&err, TaskStatus::Pending, to));
    }
    assert_eq!(b.get(t.id).unwrap().status, TaskStatus::Pending);
}

#[test]
fn same_status_update_is_idempotent_and_keeps_timestamp() {
    let mut b = frozen_board();
    let t = create(&mut b, "I");
    let before = b.get(t.id).unwrap().clone();
    let after = b
        .update_status(t.id, TaskStatus::Pending)
        .expect("幂等返回");
    assert_eq!(before, after, "同状态返回同一任务");
    assert_eq!(
        after.updated_at_ms, before.created_at_ms,
        "幂等不刷新时间戳"
    );

    // 已 InProgress 再设 InProgress 同样幂等。
    b.update_status(t.id, TaskStatus::InProgress).unwrap();
    let stamped = b.get(t.id).unwrap().updated_at_ms;
    let again = b.update_status(t.id, TaskStatus::InProgress).unwrap();
    assert_eq!(again.updated_at_ms, stamped);
    assert_eq!(again.status, TaskStatus::InProgress);
}

#[test]
fn status_update_refreshes_updated_at_only() {
    let mut b = board();
    let t = create(&mut b, "U");
    let created = t.created_at_ms;
    let moved = b.update_status(t.id, TaskStatus::InProgress).unwrap();
    assert_eq!(moved.updated_at_ms, created + 1, "注入时钟每次 +1ms");
    assert_eq!(moved.created_at_ms, created, "created_at 不随状态变化");
}

#[test]
fn terminal_flags_match_state_machine() {
    // 终态标记与迁移表一致：仅 done/cancelled 为终态。
    assert!(!TaskStatus::Pending.is_terminal());
    assert!(!TaskStatus::InProgress.is_terminal());
    assert!(TaskStatus::Done.is_terminal());
    assert!(TaskStatus::Cancelled.is_terminal());
    assert_eq!(TaskStatus::ALL.len(), 4, "状态集合冻结为 4 个");
}
