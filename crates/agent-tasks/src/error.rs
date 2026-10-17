//! 任务错误（规格冻结点：变体集合）。

use crate::task::TaskStatus;

/// 看板操作错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TaskError {
    #[error("任务不存在")]
    NotFound,

    #[error("非法状态迁移: {from:?} → {to:?}")]
    InvalidTransition { from: TaskStatus, to: TaskStatus },

    #[error("subject 不能为空")]
    EmptySubject,

    #[error("JSON 处理失败: {0}")]
    Json(String),
}
