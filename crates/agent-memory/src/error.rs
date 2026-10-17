use std::path::PathBuf;

/// 记忆系统错误（fail-closed：所有失败显式上抛，不静默降级）。
#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    /// 跨会话记忆未开启（`memory.enabled = false`）。
    #[error("跨会话记忆未开启")]
    Disabled,
    /// 超出层容量上限。
    #[error("记忆超出容量上限: cap={cap} len={len}")]
    CapExceeded { cap: usize, len: usize },
    /// 文件系统错误（路径随错误上报，内容不上报）。
    #[error("记忆文件 IO 错误: {path}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// 路径逃逸（越出授权目录）。
    #[error("路径越出授权目录")]
    PathEscape,
    /// 名称为空。
    #[error("名称不能为空")]
    EmptyName,
    /// JSON 序列化错误（bundle 面向网关时使用）。
    #[error("记忆序列化失败: {0}")]
    Json(String),
}
