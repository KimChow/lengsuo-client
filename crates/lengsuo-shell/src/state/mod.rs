//! 视图状态层：三个纯结构体，为将来 GPUI 渲染供数。
//!
//! 设计约束：
//! - **无 IO、无渲染、无 async**：只有数据与显式迁移函数，便于单测覆盖每个迁移。
//! - 数据来源是 `gateway` 模块的 RPC 返回值与事件流；本层不认识网络类型，
//!   只接收已解析的结构（`GatewayEvent` 等），保证与网关实现解耦。
//! - 大结果不进状态（协议 §3）：这里只保存 `result_ref` 之类的引用与摘要文本。
//!
//! 三个状态各自对应一个视图：
//! - [`SessionListState`]：会话列表（导航/侧栏）。
//! - [`SessionStreamState`]：单会话消息流 + 事件追加 + 审批挂起。
//! - [`EnvListViewState`]：环境管理视图（v0 为占位数据模型）。

mod env;
mod session_list;
mod stream;

pub use env::{EnvEntry, EnvListViewState, EnvStatus};
pub use session_list::{SessionListItem, SessionListState, SessionStatus};
pub use stream::{
    ApprovalDecision, ApprovalState, MessageRole, PendingApproval, SessionMessage, SessionMode,
    SessionStreamState, StreamPhase, ToolRef, DEFAULT_APPROVAL_TIMEOUT_MS,
};

/// 状态层的公共错误：迁移前提不成立时拒绝，不做静默修正。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    /// 会话不存在于当前状态。
    #[error("会话 {0} 不在当前状态中")]
    UnknownSession(String),
    /// 审批不存在或已应答。
    #[error("审批 {0} 不存在或已应答")]
    UnknownApproval(String),
    /// 事件序号不连续：分页回溯锚点被破坏，必须触发重放而不是猜测。
    #[error("会话 {session} 事件序号断裂：期望 {expected}，实际 {actual}")]
    SeqGap {
        /// 归属会话。
        session: String,
        /// 期望序号。
        expected: u64,
        /// 实际序号。
        actual: u64,
    },
    /// 终态之后不再接受任何追加。
    #[error("会话 {0} 已处于终态，忽略后续写入")]
    Sealed(String),
    /// 状态机当前相位不允许该迁移。
    #[error("当前相位 {phase} 不允许操作 {action}")]
    InvalidTransition {
        /// 相位名。
        phase: String,
        /// 操作名。
        action: String,
    },
}
