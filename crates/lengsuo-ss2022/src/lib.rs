#![forbid(unsafe_code)]
//! SIP022 AES UDP 报文原语；尚无会话表和重放保护，不是可用代理服务。
pub mod crypto;
pub mod packet;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("密钥长度不匹配")]
    KeyLength,
    #[error("报文长度非法")]
    Length,
    #[error("报文认证失败")]
    Authentication,
    #[error("报文方向不匹配")]
    Direction,
    #[error("报文时间超出允许窗口")]
    Timestamp,
    #[error("响应与客户端会话不匹配")]
    ClientSession,
    #[error("发送计数器已耗尽")]
    Exhausted,
    #[error("无法取得系统随机数")]
    Entropy,
    #[error("目标地址非法：{0}")]
    Address(#[from] ss_core::Error),
}
