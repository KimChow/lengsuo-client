//! 任务模型与状态机（规格冻结点：字段名、状态集合与合法迁移）。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// 任务状态；序列化为小写词（`pending|in_progress|done|cancelled`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// 已创建、尚未开始。
    #[default]
    Pending,
    /// 正在执行。
    InProgress,
    /// 已完成（终态）。
    Done,
    /// 已取消（终态）。
    Cancelled,
}

impl TaskStatus {
    /// 全部状态，用于迁移矩阵测试遍历。
    pub const ALL: [TaskStatus; 4] = [
        TaskStatus::Pending,
        TaskStatus::InProgress,
        TaskStatus::Done,
        TaskStatus::Cancelled,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            TaskStatus::Pending => "pending",
            TaskStatus::InProgress => "in_progress",
            TaskStatus::Done => "done",
            TaskStatus::Cancelled => "cancelled",
        }
    }

    /// 终态不可再迁移（同状态的幂等请求由看板单独处理）。
    pub fn is_terminal(self) -> bool {
        matches!(self, TaskStatus::Done | TaskStatus::Cancelled)
    }

    /// 状态机唯一合法迁移：Pending→InProgress→Done/Cancelled。
    pub fn can_transition(self, to: TaskStatus) -> bool {
        matches!(
            (self, to),
            (TaskStatus::Pending, TaskStatus::InProgress)
                | (TaskStatus::InProgress, TaskStatus::Done)
                | (TaskStatus::InProgress, TaskStatus::Cancelled)
        )
    }
}

/// 一个任务：隶属于某个会话，带 subject/description 与状态时间戳。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Task {
    pub id: Uuid,
    pub session_id: Uuid,
    pub subject: String,
    pub description: String,
    pub status: TaskStatus,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}
