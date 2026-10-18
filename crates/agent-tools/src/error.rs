//! 统一工具错误：安全闸、存在性、大小与组回滚分别可辨。

use std::path::PathBuf;

/// `file:*` 能力层错误。调用方（协议层）按变体映射到工具结果。
#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("路径不存在: {0:?}")]
    NotFound(PathBuf),

    #[error("越权访问或防呆拒绝: {0:?}")]
    Denied(PathBuf),

    #[error("路径已存在: {0:?}")]
    AlreadyExists(PathBuf),

    #[error("文件过大: {path:?} 超过上限 {limit} 字节")]
    TooLarge { path: PathBuf, limit: u64 },

    #[error("不是目录: {0:?}")]
    NotADirectory(PathBuf),

    #[error("重命名目标已存在: {0:?}")]
    TargetExists(PathBuf),

    #[error("批量写入在第 {failed_index} 个操作失败，已整体回滚: {reason}")]
    BatchRolledBack { failed_index: usize, reason: String },

    #[error("IO 失败 {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// 测试断言用的变体级相等：同变体且关键负载相同（`Io` 只比路径与 kind）。
impl PartialEq for ToolError {
    fn eq(&self, other: &Self) -> bool {
        use ToolError as E;
        match (self, other) {
            (E::NotFound(a), E::NotFound(b))
            | (E::Denied(a), E::Denied(b))
            | (E::AlreadyExists(a), E::AlreadyExists(b))
            | (E::NotADirectory(a), E::NotADirectory(b))
            | (E::TargetExists(a), E::TargetExists(b)) => a == b,
            (
                E::TooLarge {
                    path: p1,
                    limit: l1,
                },
                E::TooLarge {
                    path: p2,
                    limit: l2,
                },
            ) => p1 == p2 && l1 == l2,
            (
                E::BatchRolledBack {
                    failed_index: i, ..
                },
                E::BatchRolledBack {
                    failed_index: j, ..
                },
            ) => i == j,
            (
                E::Io {
                    path: p1,
                    source: s1,
                },
                E::Io {
                    path: p2,
                    source: s2,
                },
            ) => p1 == p2 && s1.kind() == s2.kind(),
            _ => false,
        }
    }
}

impl ToolError {
    /// 把 `std::io::Error` 按语义归位：不存在 / 权限 / 不是目录分别落到专门变体。
    pub(crate) fn from_io(path: PathBuf, err: std::io::Error) -> Self {
        use std::io::ErrorKind as K;
        match err.kind() {
            K::NotFound => Self::NotFound(path),
            K::PermissionDenied => Self::Denied(path),
            K::NotADirectory => Self::NotADirectory(path),
            _ => Self::Io { path, source: err },
        }
    }

    /// 把非 IO 的失败（trash 错误、回滚冲突等）包成 `Io`。
    pub(crate) fn other(path: PathBuf, msg: String) -> Self {
        Self::Io {
            path,
            source: std::io::Error::other(msg),
        }
    }
}
