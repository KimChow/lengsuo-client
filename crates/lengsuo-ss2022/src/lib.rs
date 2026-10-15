#![forbid(unsafe_code)]
//! SIP022 AES UDP 报文原语；包含内存会话与重放保护；完整运行时尚未完成，不是可用代理服务。
pub mod crypto;
pub mod packet;
pub mod receiver;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("会话策略非法")]
    SessionPolicy,
    #[error("会话容量已满")]
    SessionCapacity,
    #[error("检测到时钟回退")]
    ClockRollback,
    #[error("报文重放或计数器已过期")]
    Replay,
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
