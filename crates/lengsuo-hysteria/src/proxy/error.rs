//! 承载层错误。错误文本不包含认证密码与目标地址内容。

use crate::quic::{ConnectError, UdpSendError};

/// 承载层错误。错误文本不包含认证密码与目标地址内容。
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("QUIC 流打开失败: {0}")]
    Connect(#[from] ConnectError),
    #[error("帧编码/解码失败: {0}")]
    Frame(#[from] crate::Error),
    #[error("流写入失败: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("流读取失败: {0}")]
    Read(#[from] quinn::ReadError),
    #[error("流已关闭: {0}")]
    Closed(#[from] quinn::ClosedStream),
    #[error("对端在响应帧完成前关闭了流")]
    PrematureEof,
    #[error("响应帧超过缓冲上限")]
    ResponseTooLarge,
    #[error("目标连接被服务端拒绝: {0}")]
    Rejected(String),
    #[error("UDP 发送失败: {0}")]
    UdpSend(#[from] UdpSendError),
    #[error("服务端 UDP 发送失败: {0}")]
    ServerUdpSend(#[from] crate::quic::server::UdpSendError),
    #[error("出站 TCP 读写失败: {0}")]
    Io(#[from] std::io::Error),
}
