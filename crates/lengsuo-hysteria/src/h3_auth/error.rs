//! 认证失败类型。错误文本不携带密码本身。

use quinn::{ReadError, WriteError};

/// 认证失败类型。错误文本不携带密码本身。
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("QUIC 流打开/连接错误: {0}")]
    Quic(#[from] quinn::ConnectionError),
    #[error("帧编码失败: {0}")]
    Frame(#[from] crate::Error),
    #[error("流写入失败: {0}")]
    Write(#[from] WriteError),
    #[error("流读取失败: {0}")]
    Read(#[from] ReadError),
    #[error("流已关闭: {0}")]
    Closed(#[from] quinn::ClosedStream),
    #[error("QPACK 解码失败: {0}")]
    Qpack(#[from] crate::qpack::QpackError),
    #[error("HTTP/3 帧序列不合法: {0}")]
    Protocol(String),
    #[error("认证被拒绝：HTTP 状态 {status}（期望 233）")]
    Rejected { status: u16 },
}

impl AuthError {
    /// 是否为「0-RTT 被服务端拒绝」导致的失败。此时连接仍可继续用于
    /// 1-RTT，调用方应在同一连接上重放认证请求（参考 quinn 文档：
    /// 早数据流上的读写返回 `ZeroRttRejected`）。
    #[must_use]
    pub fn is_zero_rtt_rejected(&self) -> bool {
        matches!(
            self,
            AuthError::Write(WriteError::ZeroRttRejected)
                | AuthError::Read(ReadError::ZeroRttRejected)
        )
    }
}
