//! 统一错误类型。

use std::path::PathBuf;

use uuid::Uuid;

/// agent-core 域错误；网关层负责映射到信封 code。
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("IO 失败 {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON 处理失败: {0}")]
    Json(#[from] serde_json::Error),

    #[error("事件文件 schema 版本不支持: 文件为 {found}，本实现为 {supported}")]
    SchemaVersion { found: u32, supported: u32 },

    #[error("事件行过大: {actual} > {limit} 字节")]
    LineTooLarge { limit: usize, actual: usize },

    #[error("会话不存在: {0}")]
    SessionNotFound(Uuid),

    #[error("会话已结束，拒绝新输入: {0}")]
    SessionClosed(Uuid),

    #[error("配置非法: {0}")]
    InvalidConfig(String),

    #[error("工具未注册: {0}")]
    ToolNotFound(String),

    #[error("审批不存在或已超时: {0}")]
    ApprovalNotFound(Uuid),

    #[error("审批已应答，不可重复: {0}")]
    ApprovalAnswered(Uuid),

    #[error("凭据/大结果引用不存在或非法: {0}")]
    BlobNotFound(String),

    #[error("能力未实现（v0 占位）: {0}")]
    Unsupported(&'static str),
}

impl From<agent_memory::MemoryError> for CoreError {
    fn from(e: agent_memory::MemoryError) -> Self {
        match e {
            agent_memory::MemoryError::Io { path, source } => Self::Io { path, source },
            other => Self::InvalidConfig(other.to_string()),
        }
    }
}
