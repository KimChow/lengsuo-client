//! 类型层错误：帧编解码与 JSON 形态的失败面。零 IO，故无传输错误变体。

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
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::MalformedMessage {
            reason: e.to_string(),
        }
    }
}
