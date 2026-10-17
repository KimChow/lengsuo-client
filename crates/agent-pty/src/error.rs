//! agent-pty 错误类型（规格冻结：`NotFound` / `AlreadyDead` / `Io`）。

/// PTY 会话操作错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PtyError {
    /// 会话 id 从未创建或已被移除。
    #[error("终端会话不存在: {0}")]
    NotFound(u64),

    /// 会话存在但子进程已退出，拒绝新的输入或尺寸变更。
    #[error("终端会话已退出: {0}")]
    AlreadyDead(u64),

    /// 底层 PTY/进程操作失败；字符串为脱敏后的原因（不含凭据）。
    #[error("PTY 操作失败: {0}")]
    Io(String),
}

impl PtyError {
    /// 把 `anyhow::Error`（portable-pty 的错误类型）收敛为 `Io` 变体。
    pub(crate) fn io(err: impl std::fmt::Display) -> Self {
        PtyError::Io(err.to_string())
    }
}
