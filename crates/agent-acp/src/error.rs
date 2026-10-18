//! crate 统一错误。
//!
//! P1 只有类型层失败面（零 IO）；P2 接入传输与会话后新增 [`Error::Transport`]
//! 与 [`Error::Io`]，原有变体与语义不变。

use thiserror::Error;

/// crate 统一错误。
#[derive(Debug, Error)]
pub enum Error {
    /// JSON 序列化/反序列化失败（含类型不匹配）。
    #[error("JSON 消息编解码失败: {reason}")]
    MalformedMessage { reason: String },

    /// 单帧超过配置上限：拒绝继续（防御超长帧耗尽内存）。
    #[error("帧超长：超过 {limit} 字节上限")]
    FrameTooLarge { limit: usize },

    /// 行帧解码器进入不可恢复状态（超长行）：字节流已无法重新对齐，
    /// 调用方必须丢弃这条连接，不得跳字节继续读（fail-closed）。
    #[error("解码器已损坏: {reason}")]
    Broken { reason: String },

    /// 传输层失败（P2）：管道读写错误、对端退出、连接被判定不可信（poison）、
    /// 会话拆除中或请求超时。
    #[error("传输失败: {reason}")]
    Transport { reason: String },

    /// 底层 IO 错误（P2）：子进程管道等 std IO 失败。
    #[error("IO 错误: {reason}")]
    Io { reason: String },
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::MalformedMessage {
            reason: e.to_string(),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io {
            reason: e.to_string(),
        }
    }
}
