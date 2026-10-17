//! 错误类型测试：变体冻结、Display 文案可用于网关 msg、可比较（便于上层断言）。

use agent_tasks::{TaskError, TaskStatus};

#[test]
fn error_variants_render_readable_messages() {
    assert_eq!(TaskError::NotFound.to_string(), "任务不存在");
    assert_eq!(TaskError::EmptySubject.to_string(), "subject 不能为空");
    assert_eq!(
        TaskError::Json("坏数据".into()).to_string(),
        "JSON 处理失败: 坏数据"
    );
    let err = TaskError::InvalidTransition {
        from: TaskStatus::Done,
        to: TaskStatus::Pending,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("非法状态迁移") && msg.contains("Done") && msg.contains("Pending"),
        "文案应带方向: {msg}"
    );
}

#[test]
fn invalid_transition_carries_both_ends() {
    // 迁移记录 from/to，供上层做精确错误码与提示。
    let err = TaskError::InvalidTransition {
        from: TaskStatus::Pending,
        to: TaskStatus::Cancelled,
    };
    match err {
        TaskError::InvalidTransition { from, to } => {
            assert_eq!(from, TaskStatus::Pending);
            assert_eq!(to, TaskStatus::Cancelled);
        }
        other => panic!("变体不符: {other:?}"),
    }
}

#[test]
fn errors_are_comparable_and_cloneable() {
    let a = TaskError::NotFound;
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(a, TaskError::EmptySubject);
}
